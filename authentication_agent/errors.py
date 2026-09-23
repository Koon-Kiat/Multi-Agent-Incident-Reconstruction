"""Sanitized operational errors; event contents are never put in diagnostics."""


class InvestigationError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
