"""Read-only display adapter for previously written evaluation result schemas.

These identifiers remain only to render original saved results. This adapter does
not validate, rescore, write, or change their recorded provenance or measurements.
"""

from copy import deepcopy

from incident_reconstruction.terminology import GENERALIST, RULES_ONLY, SPECIALIST, VERIFIED_SPECIALIST

LEGACY_CONFIGURATIONS = {
    "B_single_agent": GENERALIST,
    "C_multi_agent_no_verifier": SPECIALIST,
    "D_full_mair": VERIFIED_SPECIALIST,
}
LEGACY_RULES_ONLY = "configuration_A_rules_only"


def display_results(results: dict) -> dict:
    """Return a display copy; never modify the caller's historical result object."""
    if results.get("schema_version") not in ("evaluation-results-v1", "evaluation-results-v2"):
        return results
    view = deepcopy(results)
    for run in view["runs"]:
        run["configuration"] = LEGACY_CONFIGURATIONS.get(run["configuration"], run["configuration"])
    view["totals"] = {LEGACY_CONFIGURATIONS.get(key, key): value for key, value in view["totals"].items()}
    if LEGACY_RULES_ONLY in view:
        view[RULES_ONLY] = view[LEGACY_RULES_ONLY]
    return view
