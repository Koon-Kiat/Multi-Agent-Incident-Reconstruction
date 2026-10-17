"""Evidence Verification & Evaluation.

``verifier``    deterministic claim verifier the Incident Reconstruction Orchestrator loads
``agent``       independently prompted verifier model that may only lower a verdict
``evaluation``  scoring harness: reconstruction accuracy, evidence support and latency per configuration

Nothing under ``verifier`` or ``agent`` reads ``ground_truth/``; only ``evaluation`` does, and only
after a run has been written.
"""
