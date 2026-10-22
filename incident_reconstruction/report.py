"""Static HTML incident reports and a cross-mode index, built from saved run files.

``python -m incident_reconstruction.report --corpus out/corpus --runs out/runs`` reads every
``<runs>/<mode>/<scenario>.reconstruction.json`` (plus the pipeline, orchestration and
verification files beside it) and writes ``<scenario>.report.html`` next to them and
``<runs>/index.html`` over all of them. The pipeline CLI calls the same code after each run.

Each page is a single self-contained file: inline CSS, no scripts, no external resources.
Every value taken from a run file or an event is HTML-escaped; event contents are untrusted.
Verification verdicts are shown exactly as the verifier recorded them, next to each claim and
never merged into it; a claim with no decision is shown as having none.
"""

from __future__ import annotations

import argparse
import sys
from html import escape
from pathlib import Path, PureWindowsPath

from event_processing.query import EventStore

from .claims import Claim, Reconstruction
from .models import OrchestrationRun
from .pipeline import MODES, PipelineSummary
from .stages import TRIGGER_FIELDS
from .verification import VerificationDecision, VerificationReport

MAX_VALUE_CHARS = 300
EVIDENCE_FIELDS = (*TRIGGER_FIELDS, "ProcessGuid", "ParentProcessGuid")
from .terminology import MODE_LABELS


def write_reports(runs_dir: Path | str, store: EventStore) -> tuple[Path, ...]:
    """Render every saved run under ``runs_dir`` and the index; returns the files written."""
    root = Path(runs_dir)
    written, rows = [], []
    for mode in MODES:
        for path in sorted((root / mode).glob("*.reconstruction.json")):
            bundle = _load(path)
            page = path.with_name(f"{bundle['reconstruction'].scenario_id}.report.html")
            page.write_text(render_scenario(store=store, **bundle), encoding="utf-8", newline="\n")
            written.append(page)
            rows.append((bundle, page.relative_to(root)))
    index = root / "index.html"
    index.write_text(render_index(rows), encoding="utf-8", newline="\n")
    return (*written, index)


def render_scenario(*, reconstruction: Reconstruction, store: EventStore, summary: PipelineSummary | None = None,
                    orchestration: OrchestrationRun | None = None,
                    verification: VerificationReport | None = None) -> str:
    r = reconstruction
    decisions = {d.claim_id: d for d in verification.decisions} if verification else {}
    # The placeholder's reason is the same for every claim and is stated once in the banner.
    show_reasons = verification is not None and verification.verifier.get("verifier") != "pending"
    title = f"{r.scenario_id} · {MODE_LABELS.get(r.mode, r.mode)}"
    body = [
        f"<header><p class=eyebrow>MAIR incident reconstruction</p><h1>{_e(title)}</h1>",
        _facts(r, summary),
        "</header>",
        _verification_banner(r, verification),
        _phases(summary),
        _gaps(r, orchestration),
        "<section><h2>Timeline</h2>",
        "<p class=muted>Claims are ordered by their first cited event. Each lists the records it relies on; "
        "open “Evidence” to see them as recorded.</p>" if r.claims else "<p class=muted>No claims were produced.</p>",
        "<ol class=timeline>",
        *(_claim(claim, store, decisions.get(claim.claim_id), verification is not None, show_reasons)
          for claim in r.claims),
        "</ol></section>",
        _footer(r, verification),
    ]
    return _page(title, "\n".join(part for part in body if part))


def render_index(rows: list[tuple[dict, Path]]) -> str:
    scenarios = sorted({bundle["reconstruction"].scenario_id for bundle, _ in rows})
    by_key = {(bundle["reconstruction"].scenario_id, bundle["reconstruction"].mode): (bundle, link)
              for bundle, link in rows}
    head = "".join(f"<th>{_e(MODE_LABELS[mode])}</th>" for mode in MODES)
    lines = []
    for scenario in scenarios:
        cells = []
        for mode in MODES:
            if (scenario, mode) not in by_key:
                cells.append("<td class=muted>not run</td>")
                continue
            bundle, link = by_key[(scenario, mode)]
            r, summary, verification = bundle["reconstruction"], bundle["summary"], bundle["verification"]
            details = [f"{len(r.claims)} claims"]
            if summary:
                details += [f"{summary.latency_seconds:g}s", f"{summary.model_calls} model calls"]
            if verification:
                counts = {}
                for d in verification.decisions:
                    counts[d.verdict] = counts.get(d.verdict, 0) + 1
                details.append(", ".join(f"{n} {v.replace('_', ' ')}" for v, n in sorted(counts.items())))
            cells.append(f"<td><a href=\"{_e(link.as_posix())}\">Open report</a>"
                         f"<div class=small>{_e(' · '.join(details))}</div></td>")
        lines.append(f"<tr><th scope=row>{_e(scenario)}</th>{''.join(cells)}</tr>")
    table = (f"<div class=scroll><table class=index><thead><tr><th>Scenario</th>{head}</tr></thead>"
             f"<tbody>{''.join(lines)}</tbody></table></div>") if lines else "<p class=muted>No saved runs found.</p>"
    body = ("<header><p class=eyebrow>MAIR incident reconstruction</p><h1>Run index</h1>"
            "<p class=muted>One report per scenario and configuration. Latency depends on the machine and model "
            "recorded in each run; compare runs from the same machine only.</p></header>"
            f"<section>{table}</section>")
    return _page("MAIR run index", body)


# --- page parts ------------------------------------------------------------------------------

def _facts(r: Reconstruction, summary: PipelineSummary | None) -> str:
    model = r.llm.get("model") or r.llm.get("runtime") or "none"
    facts = [("Model", model), ("Claims", len(r.claims)),
             ("Model calls", summary.model_calls if summary else r.model_calls),
             ("Corpus", r.corpus_manifest_sha256[:12])]
    if summary:
        facts[2:2] = [("Detections", summary.detections), ("Latency", f"{summary.latency_seconds:g} s")]
        facts.append(("Started", summary.started_utc))
    if r.llm.get("runtime") == "fake":
        facts.append(("Note", "deterministic fake model: plumbing check, not a quality result"))
    return "<dl class=facts>" + "".join(f"<div><dt>{_e(k)}</dt><dd>{_e(v)}</dd></div>" for k, v in facts) + "</dl>"


def _verification_banner(r: Reconstruction, verification: VerificationReport | None) -> str:
    if verification is None:
        text = ("This configuration has no verification stage. Claims are the reconstruction's own reading of the "
                "evidence and have not been independently checked.")
        return f"<aside class='banner neutral'><strong>Not verified.</strong> {_e(text)}</aside>"
    note = verification.verifier.get("note")
    pending = verification.verifier.get("verifier") == "pending"
    notes = "".join(f"<li>{_e(n)}</li>" for n in verification.integrity_notes)
    text = (f"Verifier: {verification.verifier.get('verifier', 'unknown')}" + (f" — {note}" if note else "")
            + ". Verdicts below are shown exactly as the verifier returned them.")
    kind = "warn" if pending or verification.integrity_notes else "neutral"
    return (f"<aside class='banner {kind}'><strong>{'Verification pending.' if pending else 'Verified separately.'}"
            f"</strong> {_e(text)}{f'<ul>{notes}</ul>' if notes else ''}</aside>")


def _phases(summary: PipelineSummary | None) -> str:
    if not summary or not summary.phases:
        return ""
    total = max(sum(p.seconds for p in summary.phases), 1e-9)
    rows = "".join(
        f"<div class=phase><span>{_e(p.phase.replace('_', ' '))}</span>"
        f"<span class=bar><span style='width:{max(p.seconds / total * 100, 0.5):.1f}%'></span></span>"
        f"<span class=num>{p.seconds:g} s</span></div>" for p in summary.phases)
    return f"<section><h2>Timing</h2><div class=phases>{rows}</div></section>"


def _gaps(r: Reconstruction, orchestration: OrchestrationRun | None) -> str:
    items = list(r.investigation_gaps)
    if orchestration:
        items += [f"detection {d} had no completed agent investigation" for d in orchestration.uninvestigated_detection_ids()
                  if f"detection {d} had no completed agent investigation" not in items]
    unlinked = ", ".join(f"{n} {agent}" for agent, n in r.unlinked_findings.items() if n)
    extra = (f"<p class=muted>Agent findings not attached to any claim: {_e(unlinked)}. They remain in the "
             "orchestration file.</p>") if unlinked else ""
    if not items and not extra:
        return ""
    listed = "".join(f"<li>{_e(item)}</li>" for item in items)
    return (f"<section><h2>Investigation gaps</h2>{f'<ul class=gaps>{listed}</ul>' if listed else ''}{extra}"
            "</section>")


def _claim(claim: Claim, store: EventStore, decision: VerificationDecision | None, verified_mode: bool,
           show_reason: bool = True) -> str:
    badges = [f"<span class='badge assess-{_e(claim.assessment)}'>{_e(claim.assessment.replace('_', ' '))}</span>"]
    if verified_mode:
        verdict = decision.verdict if decision else "no decision"
        badges.append(f"<span class='badge verdict-{_e(verdict.replace(' ', '_'))}'>verifier: "
                      f"{_e(verdict.replace('_', ' '))}</span>")
    if claim.narrative_source == "template":
        badges.append("<span class='badge template'>template text</span>")
    attack = "".join(
        f"<li class='technique status-{_e(m.status)}'><span class=tid>{_e(m.technique_id)}</span> {_e(m.name)}"
        f" <span class=small>({_e(m.status)}{'; ' + _e(', '.join(m.tactics)) if m.tactics else ''})</span>"
        f"<div class=small>{_e(m.justification)}</div></li>" for m in claim.attack)
    related = ", ".join(f"<a href='#{_e(link.claim_id)}'>{_e(link.claim_id)}</a> ({_e(link.reason)})"
                        for link in claim.related_claims)
    verdict_block = ""
    if decision and show_reason:
        conflicts = "".join(f"<li>{_e(c)}</li>" for c in decision.conflicts)
        verdict_block = (f"<div class=verdict><strong>Verifier reason:</strong> {_e(decision.reason)}"
                         f"{f'<ul>{conflicts}</ul>' if conflicts else ''}</div>")
    uncertainty = "".join(f"<li>{_e(u)}</li>" for u in claim.uncertainty)
    return f"""<li class=claim id="{_e(claim.claim_id)}">
<div class=claim-head><span class=pos>{claim.position}</span><div>
<p class=small><span class=mono>{_e(claim.claim_id)}</span> · {_e(claim.claim_type.replace('_', ' '))} ·
<time>{_e(claim.first_utc)}</time>{'' if claim.first_utc == claim.last_utc else f' → <time>{_e(claim.last_utc)}</time>'}</p>
<p class=badges>{''.join(badges)}</p></div></div>
<p class=claim-text>{_e(claim.claim_text)}</p>
<p class=rationale>{_e(claim.rationale)}</p>
{verdict_block}
{_entities(claim)}
{f'<h3>ATT&amp;CK (tentative mapping)</h3><ul class=attack>{attack}</ul>' if attack else ''}
{f'<p class=small><strong>Related:</strong> {related}</p>' if related else ''}
{f'<details class=uncertainty><summary>Uncertainty ({len(claim.uncertainty)})</summary><ul>{uncertainty}</ul></details>' if uncertainty else ''}
{_evidence(claim, store)}
</li>"""


def _entities(claim: Claim) -> str:
    e = claim.entities
    rows = [("Accounts", e.accounts), ("Hosts", e.hosts),
            ("Processes", tuple(dict.fromkeys(PureWindowsPath(p).name for p in e.processes))), ("Files", e.files)]
    cells = "".join(f"<div><dt>{name}</dt><dd>{', '.join(_e(v) for v in values[:8])}"
                    f"{f' +{len(values) - 8} more' if len(values) > 8 else ''}</dd></div>"
                    for name, values in rows if values)
    return f"<dl class=entities>{cells}</dl>" if cells else ""


def _evidence(claim: Claim, store: EventStore) -> str:
    rows = []
    for evidence_id in claim.evidence_ids:
        event = store.lookup(evidence_id).event
        if event is None:
            rows.append(f"<tr><td class=mono>{_e(evidence_id)}</td><td colspan=4 class=bad>not found in this corpus</td></tr>")
            continue
        fields = "".join(f"<div><span class=key>{_e(name)}</span> {_e(_clip(event.event_data[name]))}</div>"
                         for name in EVIDENCE_FIELDS if event.event_data.get(name))
        rows.append(f"<tr><td class=mono>{_e(evidence_id)}</td><td><time>{_e(event.timestamp_utc)}</time></td>"
                    f"<td>{_e(event.channel.split('/')[0])} {event.source_event_id}</td>"
                    f"<td>{_e(event.host or '')}<br>{_e(event.user or '')}</td>"
                    f"<td class=fields>{fields}<div class=small>{_e(event.raw_reference)}</div></td></tr>")
    sources = ""
    if claim.detection_ids or claim.supporting_finding_ids:
        sources = (f"<p class=small><strong>Detections:</strong> {_e(', '.join(claim.detection_ids) or 'none')}<br>"
                   f"<strong>Agent findings:</strong> {_e(', '.join(claim.supporting_finding_ids) or 'none')}</p>")
    extra = len(claim.context_evidence_ids) - len(claim.evidence_ids)
    context = f"<p class=small>{extra} further records were available to this stage but not cited.</p>" if extra > 0 else ""
    return (f"<details class=evidence><summary>Evidence ({len(claim.evidence_ids)} cited)</summary>"
            f"<div class=scroll><table><thead><tr><th>Evidence ID</th><th>Time (UTC)</th><th>Source</th>"
            f"<th>Host / user</th><th>Recorded fields</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
            f"{sources}{context}</details>")


def _footer(r: Reconstruction, verification: VerificationReport | None) -> str:
    parts = [r.schema_version, r.prompt_version]
    if verification:
        parts.append(verification.schema_version)
    return f"<footer class=small>Generated from {_e(' · '.join(parts))}. Read-only; no event was modified.</footer>"


# --- loading and helpers ---------------------------------------------------------------------

def _load(path: Path) -> dict:
    scenario = path.name.removesuffix(".reconstruction.json")
    sibling = lambda kind: path.with_name(f"{scenario}.{kind}.json")
    read = lambda kind, model: model.model_validate_json(sibling(kind).read_text(encoding="utf-8")) \
        if sibling(kind).is_file() else None
    return {"reconstruction": Reconstruction.model_validate_json(path.read_text(encoding="utf-8")),
            "summary": read("pipeline", PipelineSummary),
            "orchestration": read("orchestration", OrchestrationRun),
            "verification": read("verification", VerificationReport)}


def _clip(value: str) -> str:
    return value if len(value) <= MAX_VALUE_CHARS else value[:MAX_VALUE_CHARS - 1] + "…"


def _e(value) -> str:
    return escape(str(value), quote=True)


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>{CSS}</style></head>
<body><main>{body}</main></body></html>
"""


CSS = """
:root{--bg:#f7f7f5;--surface:#fff;--text:#1d1f23;--muted:#5d636d;--line:#dcdfe3;--accent:#1f5f8b;
--good:#1e7a46;--warn:#9a5b00;--bad:#b3261e;--soft-warn:#fff4e0;--soft-bad:#fdecea;--soft-good:#e8f5ed;
--soft:#eef1f4;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#15171a;--surface:#1d2024;--text:#e6e8eb;--muted:#a1a7b0;
--line:#33373d;--accent:#7cb7e0;--good:#6fcf97;--warn:#f2b45c;--bad:#f28b82;--soft-warn:#3a2c14;
--soft-bad:#3b1f1d;--soft-good:#1c3326;--soft:#262a2f;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:1.7rem;margin:.1em 0 .4em}h2{font-size:1.15rem;margin:2em 0 .6em}h3{font-size:.95rem;margin:1em 0 .3em}
a{color:var(--accent)}.eyebrow{text-transform:uppercase;letter-spacing:.08em;font-size:.75rem;color:var(--muted);margin:0}
.muted,.small{color:var(--muted)}.small{font-size:.85rem}.mono,.tid{font-family:ui-monospace,Consolas,monospace;font-size:.85em}
.facts,.entities{display:flex;flex-wrap:wrap;gap:8px 24px;margin:0}.facts dt,.entities dt{font-size:.75rem;color:var(--muted)}
.facts dd,.entities dd{margin:0;font-weight:500;overflow-wrap:anywhere}
.banner{border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:20px 0;background:var(--surface)}
.banner.warn{background:var(--soft-warn);border-color:var(--warn)}.banner ul{margin:.4em 0 0}
.phases{display:grid;gap:6px}.phase{display:grid;grid-template-columns:130px 1fr 80px;gap:12px;align-items:center}
.bar{height:10px;background:var(--soft);border-radius:5px;overflow:hidden}.bar span{display:block;height:100%;background:var(--accent)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.gaps li{margin:.2em 0}
.timeline{list-style:none;padding:0;margin:0;display:grid;gap:16px}
.claim{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.claim:target{outline:2px solid var(--accent)}
.claim-head{display:flex;gap:12px;align-items:flex-start}.claim-head p{margin:0}
.pos{flex:none;width:30px;height:30px;border-radius:50%;background:var(--soft);display:grid;place-items:center;font-weight:600}
.claim-text{font-size:1.02rem;font-weight:500;margin:.8em 0 .3em}.rationale{color:var(--muted);margin:0 0 .8em}
.badges{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px!important}
.badge{font-size:.75rem;padding:2px 8px;border-radius:999px;border:1px solid var(--line);background:var(--soft)}
.assess-requires_review,.verdict-rejected{background:var(--soft-bad);border-color:var(--bad)}
.assess-benign_possible,.verdict-confirmed{background:var(--soft-good);border-color:var(--good)}
.verdict-partially_supported,.verdict-unverified,.verdict-no_decision,.template{background:var(--soft-warn);border-color:var(--warn)}
.verdict{border-left:3px solid var(--accent);padding:4px 10px;margin:8px 0;background:var(--soft)}
.attack{list-style:none;padding:0;margin:0;display:grid;gap:6px}
.technique{border-left:3px solid var(--line);padding-left:10px}
.status-supported{border-color:var(--good)}.status-tentative{border-color:var(--warn)}.status-uncertain{border-color:var(--line)}
details{margin-top:10px}summary{cursor:pointer;color:var(--accent)}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.85rem;margin-top:8px}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.fields div{overflow-wrap:anywhere}.key{color:var(--muted);font-size:.8em}.bad{color:var(--bad)}
table.index td{min-width:180px}footer{margin-top:40px}
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="incident_reconstruction.report", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True, help="normalised corpus the runs were made from")
    parser.add_argument("--runs", type=Path, required=True, help="run output root (contains <mode>/ directories)")
    args = parser.parse_args(argv)
    try:
        store = EventStore.load(args.corpus)
        written = write_reports(args.runs, store)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
