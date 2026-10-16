from pathlib import Path
from collections.abc import Callable

from checks.rules import Check, default_checks
from model.finding import Finding
from model.settings import Settings
from workspace.files import project_files
from workspace.git import staged_mismatch_findings


class Scanner:
    def __init__(
        self,
        settings: Settings,
        checks: tuple[Check, ...] | None = None,
        list_files: Callable[..., list[Path]] | None = None,
        mismatch_findings: Callable[..., list[Finding]] | None = None,
    ) -> None:
        self.settings = settings
        self.checks = checks or default_checks()
        self.list_files = list_files
        self.mismatch_findings = mismatch_findings

    def run(self, project: Path) -> list[Finding]:
        if self.list_files is None or self.mismatch_findings is None:
            list_files = self.list_files or project_files
            mismatch_findings = self.mismatch_findings or staged_mismatch_findings
        else:
            list_files = self.list_files
            mismatch_findings = self.mismatch_findings

        findings: list[Finding] = []
        files = list_files(project, self.settings.exclude, findings)
        findings.extend(mismatch_findings(project, self.settings.exclude))
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
