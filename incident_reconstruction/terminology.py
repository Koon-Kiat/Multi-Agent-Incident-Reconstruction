"""Canonical evaluation names, independent of stable pipeline command modes."""

RULES_ONLY = "rules_only_detection_baseline"
GENERALIST = "single_agent_generalist_baseline"
SPECIALIST = "specialist_agent_incident_reconstruction"
VERIFIED_SPECIALIST = "specialist_agent_incident_reconstruction_with_independent_evidence_verification"

EVALUATION_NAMES = {
    RULES_ONLY: "Rules-only Detection Baseline",
    GENERALIST: "Single-Agent Generalist Baseline",
    SPECIALIST: "Specialist-Agent Incident Reconstruction",
    VERIFIED_SPECIALIST: "Specialist-Agent Incident Reconstruction with Independent Evidence Verification",
}
EVALUATION_CONFIGURATIONS = {
    "single-agent": GENERALIST,
    "multi-agent": SPECIALIST,
    "full": VERIFIED_SPECIALIST,
}
MODE_LABELS = {mode: EVALUATION_NAMES[identifier] for mode, identifier in EVALUATION_CONFIGURATIONS.items()}
