from pathlib import Path

from checks.rules import Check
from model.finding import Finding
from model.settings import Settings
from workspace.exclusions import Exclusions
from workspace.files import ProjectFiles
from workspace.git import GitWorkspace


class Scanner:
    def __init__(self, settings: Settings, checks: tuple[Check, ...] | None = None) -> None:
        self.settings = settings
        self.checks = checks or Check.defaults()

    def run(self, project: Path) -> list[Finding]:
        findings: list[Finding] = []
        excluded = Exclusions(self.settings.exclude)
        files = ProjectFiles(project, excluded).collect(findings)
        findings.extend(GitWorkspace(project).mismatch_findings(excluded))
        limit = self.settings.max_size_mib
        once = [check for check in self.checks if not check.each_file]
        per_file = [check for check in self.checks if check.each_file]
        for check in once:
            findings.extend(check.apply(project, files, limit))
        for path in files:
            one = [path]
            for check in per_file:
                findings.extend(check.apply(project, one, limit))
        return findings
