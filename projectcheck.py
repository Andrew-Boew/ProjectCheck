import argparse
import os
from pathlib import Path
import tempfile

from constants import DEFAULT_MAX_SIZE_MIB
from model.finding import format_finding, make_finding
from model.report import Report
from model.settings import Settings, load_config
from scanner import Scanner
from workspace.files import project_files
from workspace.git import git_project_files, install_hook, staged_files, staged_mismatch_findings

__all__ = [
    "git_project_files",
    "install_hook",
    "load_config",
    "main",
    "make_finding",
    "project_files",
    "scan",
    "scan_details",
]


def scan_details(project: Path, max_size_mib: int = DEFAULT_MAX_SIZE_MIB, excludes: tuple[str, ...] = ()) -> list:
    return Scanner(
        Settings(max_size_mib, excludes),
        list_files=project_files,
        mismatch_findings=staged_mismatch_findings,
    ).run(project)


def scan(project: Path, max_size_mib: int = DEFAULT_MAX_SIZE_MIB, excludes: tuple[str, ...] = ()) -> list[str]:
    return [format_finding(item) for item in scan_details(project, max_size_mib, excludes)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка локального проекта")
    parser.add_argument("project", type=Path, help="путь к проекту")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="формат отчёта")
    parser.add_argument("--fail-on-findings", action="store_true", help="код 1 при наличии замечаний")
    parser.add_argument("--fail-on-security", action="store_true", help="код 1 только при находках безопасности")
    parser.add_argument("--staged", action="store_true", help="проверить подготовленные к коммиту файлы")
    parser.add_argument("--install-hook", action="store_true", help="установить pre-commit hook")
    parser.add_argument("--max-size-mib", type=int, help="порог большого файла в МиБ")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="исключить путь или шаблон")
    args = parser.parse_args()

    project = args.project.expanduser().resolve()
    if not project.is_dir():
        parser.error(f"папка не найдена: {project}")
    if args.install_hook:
        try:
            hook = install_hook(project)
        except ValueError as error:
            parser.error(str(error))
        print(f"Установлен pre-commit hook: {hook}")
        return 0

    try:
        settings = Settings.load(project)
    except ValueError as error:
        parser.error(str(error))
    max_size_mib = args.max_size_mib if args.max_size_mib is not None else settings.max_size_mib
    if max_size_mib <= 0:
        parser.error("--max-size-mib должен быть положительным числом")
    excludes = settings.exclude + tuple(args.exclude)

    if args.staged:
        try:
            with tempfile.TemporaryDirectory() as directory:
                snapshot = Path(directory)
                staged_files(project, snapshot)
                findings = scan_details(snapshot, max_size_mib=max_size_mib, excludes=excludes)
        except ValueError as error:
            parser.error(str(error))
    else:
        findings = scan_details(project, max_size_mib=max_size_mib, excludes=excludes)
    report = Report(findings, args.format)
    print(report.render(project))
    return report.exit_code(args.fail_on_findings, args.fail_on_security)


if __name__ == "__main__":
    raise SystemExit(main())
