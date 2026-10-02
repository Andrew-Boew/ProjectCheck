import argparse
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
DEFAULT_MAX_SIZE_MIB = 10
TEMP_SUFFIXES = {".tmp", ".bak", ".swp", ".swo"}
PRIVATE_KEY_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template"}


def has_sensitive_name(path: Path) -> bool:
    name = path.name.lower()
    return (
        (name == ".env" or name.startswith(".env.")) and name not in ENV_TEMPLATES
    ) or name in PRIVATE_KEY_NAMES or path.suffix.lower() in {".key", ".p12", ".pfx"}


def is_excluded(relative: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/"):
            if relative == pattern.rstrip("/") or relative.startswith(pattern):
                return True
        elif fnmatchcase(relative, pattern):
            return True
    return False


def project_files(project: Path, excludes: tuple[str, ...] = ()) -> list[Path]:
    files = []
    for directory, subdirs, names in os.walk(project):
        subdirs[:] = sorted(
            name for name in subdirs
            if name not in IGNORED_DIRS
            and not (Path(directory) / name).is_symlink()
            and not is_excluded((Path(directory) / name).relative_to(project).as_posix(), excludes)
        )
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_file() and not path.is_symlink() and not is_excluded(path.relative_to(project).as_posix(), excludes):
                files.append(path)
    return files


def scan(project: Path, max_size_mib: int = DEFAULT_MAX_SIZE_MIB, excludes: tuple[str, ...] = ()) -> list[str]:
    findings = []
    files = project_files(project, excludes)
    if not any((project / name).is_file() for name in ("README.md", "README.rst", "README.txt")):
        findings.append("README: добавьте описание проекта")
    if not (project / ".gitignore").is_file():
        findings.append("GITIGNORE: добавьте .gitignore")
    if not any(
        path.suffix == ".py" and (path.name.startswith("test_") or path.stem.endswith("_test"))
        for path in files
    ):
        findings.append("TESTS: тесты не найдены")

    for path in files:
        relative = path.relative_to(project).as_posix()
        if has_sensitive_name(path):
            findings.append(f"SENSITIVE: проверьте потенциально конфиденциальный файл {relative}")
        if path.suffix.lower() in TEMP_SUFFIXES or path.name.endswith("~") or path.name == ".DS_Store":
            findings.append(f"TEMP: временный файл {relative}")
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_size_mib * 1024 * 1024:
            findings.append(f"LARGE: файл больше {max_size_mib} МиБ {relative}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка локального проекта")
    parser.add_argument("project", type=Path, help="путь к проекту")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="формат отчёта")
    parser.add_argument("--fail-on-findings", action="store_true", help="код 1 при наличии замечаний")
    parser.add_argument("--max-size-mib", type=int, default=DEFAULT_MAX_SIZE_MIB, help="порог большого файла в МиБ")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="исключить путь или шаблон")
    args = parser.parse_args()

    if args.max_size_mib <= 0:
        parser.error("--max-size-mib должен быть положительным числом")

    project = args.project.expanduser().resolve()
    if not project.is_dir():
        parser.error(f"папка не найдена: {project}")

    findings = scan(project, max_size_mib=args.max_size_mib, excludes=tuple(args.exclude))
    exit_code = 1 if args.fail_on_findings and findings else 0
    if args.format == "json":
        print(json.dumps({"project": str(project), "count": len(findings), "findings": findings}, ensure_ascii=False, indent=2))
        return exit_code

    if findings:
        for finding in findings:
            print(f"- {finding}")
        print(f"Найдено замечаний: {len(findings)}")
    else:
        print("Замечаний не найдено")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
