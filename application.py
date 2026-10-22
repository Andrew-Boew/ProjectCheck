import argparse
from pathlib import Path
import tempfile
from typing import NoReturn

from model.finding import Finding
from model.report import Report
from model.settings import Settings
from model.view import Console, ReportJson, ReportText
from scanner import Scanner
from workspace.git import GitWorkspace


class CommandLine:
    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(description="Проверка локального проекта")
        self.parser.add_argument("project", type=Path, help="путь к проекту")
        self.parser.add_argument("--format", choices=("text", "json"), default="text", help="формат отчёта")
        self.parser.add_argument("--fail-on-findings", action="store_true", help="код 1 при наличии замечаний")
        self.parser.add_argument("--fail-on-security", action="store_true", help="код 1 только при находках безопасности")
        self.parser.add_argument("--staged", action="store_true", help="проверить подготовленные к коммиту файлы")
        self.parser.add_argument("--install-hook", action="store_true", help="установить pre-commit hook")
        self.parser.add_argument("--max-size-mib", type=int, help="порог большого файла в МиБ")
        self.parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="исключить путь или шаблон")

    def read(self) -> "CommandLine":
        args = self.parser.parse_args()
        project = args.project.expanduser().resolve()
        if not project.is_dir():
            self.fail(f"папка не найдена: {project}")
        self.project = project
        self.output_format = args.format
        self.fail_on_findings = args.fail_on_findings
        self.fail_on_security = args.fail_on_security
        self.staged = args.staged
        self.install_hook = args.install_hook
        self.max_size_mib = args.max_size_mib
        self.exclude = tuple(args.exclude)
        return self

    def fail(self, message: str) -> NoReturn:
        self.parser.error(message)


class Application:
    def __init__(self, command: CommandLine) -> None:
        self.command = command
        self.console = Console()

    def run(self) -> int:
        call = self.command.read()
        if call.install_hook:
            return self.install(call.project)
        settings = self.settings(call)
        findings = self.scan(call.project, settings, call.staged)
        return self.present(call, findings)

    def install(self, project: Path) -> int:
        try:
            hook = GitWorkspace(project).install_hook()
        except ValueError as error:
            self.command.fail(str(error))
        self.console.write(f"Установлен pre-commit hook: {hook}")
        return 0

    def settings(self, call: CommandLine) -> Settings:
        try:
            return Settings.prepared(call.project, call.max_size_mib, call.exclude)
        except ValueError as error:
            self.command.fail(str(error))

    def scan(self, project: Path, settings: Settings, staged: bool) -> list[Finding]:
        if not staged:
            return Scanner(settings).run(project)
        try:
            with tempfile.TemporaryDirectory() as directory:
                snapshot = Path(directory)
                GitWorkspace(project).export_staged(snapshot)
                return Scanner(settings).run(snapshot)
        except ValueError as error:
            self.command.fail(str(error))

    def present(self, call: CommandLine, findings: list[Finding]) -> int:
        report = Report(findings)
        view = ReportJson() if call.output_format == "json" else ReportText()
        self.console.write(view.render(report, call.project))
        return report.exit_code(call.fail_on_findings, call.fail_on_security)
