import argparse
import ast
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import subprocess
import tomllib
import tokenize

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
DEFAULT_MAX_SIZE_MIB = 10
TEMP_SUFFIXES = {".tmp", ".bak", ".swp", ".swo"}
PRIVATE_KEY_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template"}
SECRET_SETTING_SUFFIXES = ("SECRET", "SECRET_KEY", "PASSWORD", "TOKEN", "API_KEY", "PRIVATE_KEY", "CREDENTIAL", "CREDENTIALS")
Finding = dict[str, str | int | None]


def make_finding(code: str, message: str, path: str | None = None, line: int | None = None, confidence: str = "high") -> Finding:
    return {"code": code, "message": message, "path": path, "line": line, "confidence": confidence}


def format_finding(item: Finding) -> str:
    path = f" {item['path']}" if item["path"] else ""
    if path and item["line"] is not None:
        path += f":{item['line']}"
    return f"{item['code']}: {item['message']}{path}"


def has_sensitive_name(path: Path) -> bool:
    name = path.name.lower()
    return (
        (name == ".env" or name.startswith(".env.")) and name not in ENV_TEMPLATES
    ) or name in PRIVATE_KEY_NAMES or path.suffix.lower() in {".key", ".p12", ".pfx"}


def is_secret_setting(name: str) -> bool:
    upper = name.upper()
    return any(upper == suffix or upper.endswith(f"_{suffix}") for suffix in SECRET_SETTING_SUFFIXES)


def python_secret_findings(path: Path, relative: str) -> list[Finding]:
    try:
        with tokenize.open(path) as file:
            tree = ast.parse(file.read(), filename=relative)
    except SyntaxError:
        return []
    except (OSError, UnicodeError) as error:
        return [make_finding("SCAN_ERROR", f"не удалось прочитать Python-файл: {error}", relative)]

    findings = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str) or not node.value.value.strip():
            continue
        for target in targets:
            if isinstance(target, ast.Name) and is_secret_setting(target.id):
                findings.append(make_finding(
                    "HARDCODED_SECRET", f"строковый литерал в {target.id}", relative, node.lineno, "medium"
                ))
    return findings


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


def project_files(project: Path, excludes: tuple[str, ...] = (), errors: list[Finding] | None = None) -> list[Path]:
    git_files = git_project_files(project, excludes)
    if git_files is not None:
        return git_files

    def on_walk_error(error: OSError) -> None:
        relative = None
        if error.filename:
            try:
                relative = Path(error.filename).resolve().relative_to(project.resolve()).as_posix()
            except ValueError:
                pass
        if errors is not None:
            errors.append(make_finding("SCAN_ERROR", f"не удалось прочитать папку: {error.strerror or error}", relative))

    files = []
    for directory, subdirs, names in os.walk(project, onerror=on_walk_error):
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
    files = project_files(project, excludes, findings)
    if not any((project / name).is_file() for name in ("README.md", "README.rst", "README.txt")):
        findings.append(make_finding("README", "добавьте описание проекта"))
    if not (project / ".gitignore").is_file():
        findings.append(make_finding("GITIGNORE", "добавьте .gitignore"))
    if not any(
        path.suffix == ".py" and (path.name.startswith("test_") or path.stem.endswith("_test"))
        for path in files
    ):
        findings.append(make_finding("TESTS", "тесты не найдены", confidence="low"))

    for path in files:
        relative = path.relative_to(project).as_posix()
        if has_sensitive_name(path):
            findings.append(make_finding("SENSITIVE", "проверьте потенциально конфиденциальный файл", relative, confidence="medium"))
        if path.name in {"settings.py", "config.py"}:
            findings.extend(python_secret_findings(path, relative))
        if path.suffix.lower() in TEMP_SUFFIXES or path.name.endswith("~") or path.name == ".DS_Store":
            findings.append(make_finding("TEMP", "временный файл", relative, confidence="medium"))
        try:
            size = path.stat().st_size
        except OSError as error:
            findings.append(make_finding("SCAN_ERROR", f"не удалось получить размер файла: {error}", relative))
            continue
        if size > max_size_mib * 1024 * 1024:
            findings.append(make_finding("LARGE", f"файл больше {max_size_mib} МиБ", relative))
    return findings


def scan(project: Path, max_size_mib: int = DEFAULT_MAX_SIZE_MIB, excludes: tuple[str, ...] = ()) -> list[str]:
    return [format_finding(item) for item in scan_details(project, max_size_mib, excludes)]


def load_config(project: Path) -> tuple[int, tuple[str, ...]]:
    path = project / ".projectcheck.toml"
    if not path.exists():
        return DEFAULT_MAX_SIZE_MIB, ()
    try:
        with path.open("rb") as file:
            config = tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"не удалось прочитать {path.name}: {error}") from error

    unknown = set(config) - {"max_size_mib", "exclude"}
    if unknown:
        raise ValueError(f"неизвестные настройки в {path.name}: {', '.join(sorted(unknown))}")
    max_size_mib = config.get("max_size_mib", DEFAULT_MAX_SIZE_MIB)
    excludes = config.get("exclude", [])
    if type(max_size_mib) is not int or max_size_mib <= 0:
        raise ValueError("max_size_mib должен быть положительным целым числом")
    if not isinstance(excludes, list) or any(not isinstance(pattern, str) or not pattern for pattern in excludes):
        raise ValueError("exclude должен быть списком непустых строк")
    return max_size_mib, tuple(excludes)


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка локального проекта")
    parser.add_argument("project", type=Path, help="путь к проекту")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="формат отчёта")
    parser.add_argument("--fail-on-findings", action="store_true", help="код 1 при наличии замечаний")
    parser.add_argument("--max-size-mib", type=int, help="порог большого файла в МиБ")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="исключить путь или шаблон")
    args = parser.parse_args()

    project = args.project.expanduser().resolve()
    if not project.is_dir():
        parser.error(f"папка не найдена: {project}")

    try:
        config_size_mib, config_excludes = load_config(project)
    except ValueError as error:
        parser.error(str(error))
    max_size_mib = args.max_size_mib if args.max_size_mib is not None else config_size_mib
    if max_size_mib <= 0:
        parser.error("--max-size-mib должен быть положительным числом")
    excludes = config_excludes + tuple(args.exclude)

    findings = scan_details(project, max_size_mib=max_size_mib, excludes=excludes)
    if any(finding["code"] == "SCAN_ERROR" for finding in findings):
        exit_code = 2
    else:
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
