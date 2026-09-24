"""Offline smoke-test model; makes no claim about model autonomy or accuracy."""


class FakeLLM:
    def metadata(self) -> dict:
        return {"runtime": "fake", "model": "endpoint-fake-v1"}

    def complete(self, messages, schema, limits) -> str:
        return '{"action":"finish","tool":null,"annotations":[]}'
