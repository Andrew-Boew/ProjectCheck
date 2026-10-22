from pathlib import Path
import json

from model.finding import Finding
from model.report import Report


class ReportText:
    def render(self, report: Report, project: Path) -> str:
        if not report.findings:
            return "Замечаний не найдено"
        lines = [f"- {self.line(item)}" for item in report.findings]
        lines.append(f"Найдено замечаний: {len(report.findings)}")
        return "\n".join(lines)

    def line(self, item: Finding) -> str:
        path = f" {item.path}" if item.path else ""
        if path and item.line is not None:
            path += f":{item.line}"
        return f"{item.code}: {item.message}{path}"


class ReportJson:
    def render(self, report: Report, project: Path) -> str:
        payload = {
            "project": str(project),
            "count": len(report.findings),
            "findings": [item.as_dict() for item in report.findings],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)


class Console:
    def write(self, text: str) -> None:
        print(text)
