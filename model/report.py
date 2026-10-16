from pathlib import Path
import json

from constants import SECURITY_CODES
from model.finding import Finding, format_finding


class Report:
    def __init__(self, findings: list[Finding], output_format: str) -> None:
        self.findings = findings
        self.format = output_format

    def exit_code(self, fail_on_findings: bool = False, fail_on_security: bool = False) -> int:
        if any(item.code == "SCAN_ERROR" for item in self.findings):
            return 2
        if fail_on_findings and self.findings:
            return 1
        if fail_on_security and any(item.code in SECURITY_CODES for item in self.findings):
            return 1
        return 0

    def render(self, project: Path) -> str:
        if self.format == "json":
            payload = {
                "project": str(project),
                "count": len(self.findings),
                "findings": [item.as_dict() for item in self.findings],
            }
            return json.dumps(payload, ensure_ascii=False, indent=2)
        if not self.findings:
            return "Замечаний не найдено"
        lines = [f"- {format_finding(item)}" for item in self.findings]
        lines.append(f"Найдено замечаний: {len(self.findings)}")
        return "\n".join(lines)
