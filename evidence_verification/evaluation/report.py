"""Renders ``results.json`` as Markdown tables: raw counts with denominators, never a headline percentage."""

from __future__ import annotations

from .scoring import ALIGNMENTS, VERDICTS

ORDER = ("B_single_agent", "C_multi_agent_no_verifier", "D_full_mair")
SHORT = {"B_single_agent": "B single-agent", "C_multi_agent_no_verifier": "C multi-agent, no verifier",
         "D_full_mair": "D full MAIR"}


def _n(value) -> str:
    return "n/a" if value is None else (f"{value:.3f}" if isinstance(value, float) else str(value))


def _table(header: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(_n(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)


def _scored(results: dict, configuration: str) -> list[dict]:
    return [r for r in results["runs"] if r["configuration"] == configuration and r["status"] == "scored"]


def render(results: dict) -> str:
    out: list[str] = ["# MAIR evaluation results", ""]
    if results["plumbing_only"]:
        out += ["> **PLUMBING ONLY.** At least one run used a deterministic fake model. These figures check that the "
                "harness works; they say nothing about investigation quality and must not be reported as results.", ""]
    prov = results["provenance"]
    out += ["## Provenance", "",
            f"- Corpus manifest SHA-256: `{results['inputs']['corpus_manifest_sha256']}`",
            f"- Code revision: `{prov['git_commit']}`; verifier code unmodified since commit: "
            f"`{prov['verifier_code_clean']}`",
            f"- Verifier version {prov['verifier']['version']}, prompt `{prov['verifier']['prompt_version']}`, "
            f"span tolerance {prov['verifier']['span_tolerance_seconds']} s",
            f"- Evaluation protocol SHA-256: public `{prov['protocol_public_sha256']}`, "
            f"private `{prov['protocol_private_sha256']}`",
            f"- Hardware: {prov['hardware']['platform']}; {prov['hardware']['logical_cpus']} logical CPUs; "
            f"{prov['hardware']['note'] or 'no hardware note given'}", ""]

    totals = results["totals"]
    out += ["## Reconstruction (unit: ground-truth stage)", "",
            "Stages matched = stages with at least one claim citing a record the key attributes to them. "
            "Order counts pairs of matched stages by whether their claims appear in the key's order (ties excluded).", ""]
    rows = []
    for configuration in ORDER:
        for run in _scored(results, configuration):
            r = run["reconstruction"]
            rows.append([SHORT[configuration], r["scenario_id"], f"{r['stages_matched']}/{r['stages_total']}",
                         f"{r['order_concordant']}/{r['order_concordant'] + r['order_discordant']}"
                         + (f" (+{r['order_ties']} ties)" if r["order_ties"] else ""),
                         r["claims_aligned"], r["claims_neutral"], r["claims_unaligned"], r["mean_stage_coverage"]])
        if configuration in totals:
            t = totals[configuration]
            rows.append([f"**{SHORT[configuration]}**", "**all**", f"**{t['stages_matched']}/{t['stages_total']}**",
                         f"**{t['order_concordant']}/{t['order_concordant'] + t['order_discordant']}**",
                         f"**{t['claims_aligned']}**", f"**{t['claims_neutral']}**", f"**{t['claims_unaligned']}**", ""])
    out += [_table(["Configuration", "Scenario", "Stages matched", "Order concordant",
                    "Claims aligned", "Neutral", "Unaligned", "Mean stage coverage"], rows), ""]

    out += ["## Does the system tell the benign lookalike from the attack? (aligned stages only)", "",
            "`true_flag`/`true_benign` are stages the claims judged as the key labels them; `under_call` is an attack "
            "stage the claims called benign or insufficient; `over_call` is a benign stage the claims flagged for review.", ""]
    rows = [[SHORT[c]] + [totals[c]["assessment"].get(k, 0) for k in ("true_flag", "under_call", "over_call", "true_benign")]
            for c in ORDER if c in totals]
    out += [_table(["Configuration", "true_flag", "under_call", "over_call", "true_benign"], rows), ""]

    out += ["## Evidence support (unit: claim; one verifier scored every configuration)", "",
            "The same deterministic verifier checked every configuration's claims, so the counts are comparable. "
            "Support is not correctness: a claim can be fully supported by real records and still describe activity "
            "the key does not attribute to any stage.", ""]
    rows = []
    for configuration in ORDER:
        if configuration in totals:
            t = totals[configuration]
            s = t["support_scoring_pass"]
            rows.append([SHORT[configuration], t["claims_total"], *(s[v] for v in VERDICTS),
                         t["fabricated_reference_claims"]])
    out += [_table(["Configuration", "Claims", *VERDICTS, "Fabricated-reference claims"], rows), ""]

    if "D_full_mair" in totals:
        t = totals["D_full_mair"]
        out += ["### Full MAIR: the verifier's verdicts against the key", "",
                "Rows are what the key says about the claim; columns are the verdict the pipeline recorded.", ""]
        rows = [[a, *(t["verifier_vs_key"][a][v] for v in VERDICTS)] for a in ALIGNMENTS]
        out += [_table(["Claim vs key", *VERDICTS], rows), "",
                f"Claims whose verdict the model layer lowered below the deterministic verdict: "
                f"**{t['claims_changed_by_agent']}** of {t['claims_total']}.", ""]

    out += ["## Latency", "", "Wall-clock seconds per scenario. One run per configuration on one machine; local model "
            "start-up and caching add variability.", ""]
    rows = []
    for configuration in ORDER:
        for run in _scored(results, configuration):
            phases = {p["phase"]: p["seconds"] for p in run["latency"]["phases"]}
            rows.append([SHORT[configuration], run["scenario_id"], run["latency"]["total_seconds"],
                         phases.get("investigation", phases.get("single_agent", "")),
                         phases.get("reconstruction", ""), phases.get("verification", ""), run["latency"]["model_calls"]])
    out += [_table(["Configuration", "Scenario", "Total s", "Investigation s", "Reconstruction s", "Verification s",
                    "Model calls"], rows), ""]

    a = results.get("configuration_A_rules_only")
    if a:
        out += ["## Configuration A: rules only (unit: evidence ID)", "", f"**{a['status']}.**", ""]
        rows = []
        for view in ("primary", "strict"):
            overall = a[view]["report"]["overall"]
            rows.append([view, overall["flagged"], overall["tp"], overall["fp"], overall["fn"], overall["flagged_excluded"],
                         overall["precision"], overall["recall"], overall["f1"]])
        out += [_table(["Label view", "Flagged", "TP", "FP", "FN", "Flagged-excluded", "Precision", "Recall", "F1"], rows), ""]

    gaps = [(r["configuration"], r["scenario_id"], g) for r in results["runs"] if r["status"] == "scored"
            for g in r["investigation_gaps"]]
    out += ["## Investigation gaps recorded by the runs", ""]
    out += [f"- {SHORT[c]} {s}: {g}" for c, s, g in gaps] or ["- none"]
    missing = [r for r in results["runs"] if r["status"] != "scored"]
    if missing:
        out += ["", "## Runs not scored", ""] + [f"- {SHORT[r['configuration']]} {r['scenario_id']}: {r['status']}" for r in missing]
    return "\n".join(out) + "\n"
