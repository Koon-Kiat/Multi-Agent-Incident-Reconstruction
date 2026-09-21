"""Deterministic model substitute that reads the same observation envelope."""

import json

from m3.config import Limits


class FakeLLM:
    def metadata(self) -> dict:
        return {"runtime": "fake", "model": "deterministic-fake-v1"}

    def complete(self, messages: list[dict[str, str]], schema: dict, limits: Limits) -> str:
        observations = json.loads(messages[-1]["content"])["observations"]
        return json.dumps({"action": "finish", "tool": None, "annotations": [
            {"observation_id": item["finding_id"], "evidence_ids": item["evidence_ids"],
             "interpretation": "may_warrant_review" if item["observed_events"]["repeated_failures_followed_by_success"] else "context_required"}
            for item in observations
        ]})
