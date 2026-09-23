"""Compare the M3 handoff to merged PR #9, without changing the checkout."""

import ast
import json
from pathlib import Path
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from authentication_agent import models
from authentication_agent.validate_synthetic import write_json_artifact

BASELINE = "4ad96da752c8752d89994b06d6db31662aa64574"


def original(path):
    return subprocess.check_output(["git", "show", BASELINE + ":" + path], cwd=ROOT, text=True)


def signature(source):
    tree = ast.parse(source)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "investigate")
    return ast.dump(function.args, include_attributes=False)


def main():
    # Execute only the repository's known baseline data model definitions.
    baseline = types.ModuleType("authentication_contract_baseline")
    sys.modules[baseline.__name__] = baseline
    exec(compile(original("authentication_agent/models.py"), "baseline-models", "exec"), baseline.__dict__)
    schemas = ("InvestigationRequest", "InvestigationResult", "RequiredOperations", "OperationReceipt",
               "QueryRequest", "QueryResult", "AuthenticationEvent")
    for name in schemas:
        assert getattr(baseline, name).model_json_schema() == getattr(models, name).model_json_schema(), name
    assert signature(original("authentication_agent/agent.py")) == signature((ROOT / "authentication_agent/agent.py").read_text())
    report = {"baseline_commit": BASELINE, "identical_json_schemas": list(schemas),
              "investigate_signature_unchanged": True, "result_version": "authentication-result-v2",
              "internal_model_reply_change": "Bounded assessment string requested by decoder; old replies still parse. No assessment is exported in results."}
    write_json_artifact(Path(__file__).resolve().parent / "contract-readback.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
