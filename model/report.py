from model.finding import Finding


class Report:
    SECURITY_CODES = {"SENSITIVE", "HARDCODED_SECRET", "PRIVATE_KEY_BLOCK"}

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings

    def exit_code(self, fail_on_findings: bool = False, fail_on_security: bool = False) -> int:
        if any(item.code == "SCAN_ERROR" for item in self.findings):
            return 2
        if fail_on_findings and self.findings:
            return 1
        if fail_on_security and any(item.code in self.SECURITY_CODES for item in self.findings):
            return 1
        return 0
