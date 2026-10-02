import argparse
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import subprocess

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
DEFAULT_MAX_SIZE_MIB = 10
TEMP_SUFFIXES = {".tmp", ".bak", ".swp", ".swo"}
PRIVATE_KEY_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template"}
Finding = dict[str, str | None]


def format_finding(item: Finding) -> str:
    path = f" {item['path']}" if item["path"] else ""
    return f"{item['code']}: {item['message']}{path}"


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


def git_project_files(project: Path, excludes: tuple[str, ...]) -> list[Path] | None:
    try:
        root = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
        )
        if root.returncode != 0 or Path(root.stdout.strip()).resolve() != project.resolve():
            return None
        result = subprocess.run(
            ["git", "-C", str(project), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            capture_output=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None

    files = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = os.fsdecode(raw_path)
        path = project / relative
        if (
            path.is_file()
            and not path.is_symlink()
            and not any(part in IGNORED_DIRS for part in Path(relative).parts)
            and not is_excluded(Path(relative).as_posix(), excludes)
        ):
            files.append(path)
    return sorted(files)


def project_files(project: Path, excludes: tuple[str, ...] = ()) -> list[Path]:
    git_files = git_project_files(project, excludes)
    if git_files is not None:
        return git_files

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


def scan_details(project: Path, max_size_mib: int = DEFAULT_MAX_SIZE_MIB, excludes: tuple[str, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    files = project_files(project, excludes)
    if not any((project / name).is_file() for name in ("README.md", "README.rst", "README.txt")):
        findings.append({"code": "README", "message": "добавьте описание проекта", "path": None})
    if not (project / ".gitignore").is_file():
        findings.append({"code": "GITIGNORE", "message": "добавьте .gitignore", "path": None})
    if not any(
        path.suffix == ".py" and (path.name.startswith("test_") or path.stem.endswith("_test"))
        for path in files
    ):
        findings.append({"code": "TESTS", "message": "тесты не найдены", "path": None})

    for path in files:
        relative = path.relative_to(project).as_posix()
        if has_sensitive_name(path):
            findings.append({"code": "SENSITIVE", "message": "проверьте потенциально конфиденциальный файл", "path": relative})
        if path.suffix.lower() in TEMP_SUFFIXES or path.name.endswith("~") or path.name == ".DS_Store":
            findings.append({"code": "TEMP", "message": "временный файл", "path": relative})
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_size_mib * 1024 * 1024:
            findings.append({"code": "LARGE", "message": f"файл больше {max_size_mib} МиБ", "path": relative})
    return findings


def scan(project: Path, max_size_mib: int = DEFAULT_MAX_SIZE_MIB, excludes: tuple[str, ...] = ()) -> list[str]:
    return [format_finding(item) for item in scan_details(project, max_size_mib, excludes)]


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

    findings = scan_details(project, max_size_mib=args.max_size_mib, excludes=tuple(args.exclude))
    exit_code = 1 if args.fail_on_findings and findings else 0
    if args.format == "json":
        print(json.dumps({"project": str(project), "count": len(findings), "findings": findings}, ensure_ascii=False, indent=2))
        return exit_code

    if findings:
        for finding in findings:
            print(f"- {format_finding(finding)}")
        print(f"Найдено замечаний: {len(findings)}")
    else:
        print("Замечаний не найдено")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
