import argparse
import ast
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import tokenize

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
DEFAULT_MAX_SIZE_MIB = 10
CONTENT_SCAN_BYTES = 2 * 1024 * 1024
TEMP_SUFFIXES = {".tmp", ".bak", ".swp", ".swo"}
PRIVATE_KEY_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template"}
SECRET_SETTING_SUFFIXES = ("SECRET", "SECRET_KEY", "PASSWORD", "TOKEN", "API_KEY", "PRIVATE_KEY", "CREDENTIAL", "CREDENTIALS")
CONFIG_FILE_NAMES = {"settings.json", "config.json", "appsettings.json", "settings.toml", "config.toml", "pyproject.toml"}
YAML_CONFIG_NAMES = {
    "settings.yml", "settings.yaml", "config.yml", "config.yaml", "application.yml", "application.yaml",
    "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "values.yml", "values.yaml",
}
NODE_LOCK_FILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}
CI_FILES = {".gitlab-ci.yml", "azure-pipelines.yml", "Jenkinsfile", ".circleci/config.yml", ".travis.yml"}
PRIVATE_KEY_HEADER = re.compile(rb"^-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----$")
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
    upper = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).replace("-", "_").upper()
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


def config_secret_findings(path: Path, relative: str) -> list[Finding]:
    try:
        if path.suffix == ".json":
            with path.open("r", encoding="utf-8-sig") as file:
                data = json.load(file)
        else:
            with path.open("rb") as file:
                data = tomllib.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        return [make_finding("SCAN_ERROR", f"не удалось разобрать конфигурацию: {error}", relative)]

    findings = []

    def inspect(value: object, key_path: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{key_path}.{key}" if key_path else str(key)
                if isinstance(child, str) and child.strip() and is_secret_setting(str(key)):
                    findings.append(make_finding(
                        "HARDCODED_SECRET", f"строковое значение поля {child_path}", relative, confidence="medium"
                    ))
                else:
                    inspect(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                inspect(child, f"{key_path}[{index}]")

    inspect(data)
    return findings


def dotenv_secret_findings(path: Path, relative: str) -> list[Finding]:
    findings = []
    try:
        with path.open("r", encoding="utf-8-sig") as file:
            for line_number, text in enumerate(file, start=1):
                match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", text)
                if not match or not is_secret_setting(match.group(1)):
                    continue
                value = match.group(2).strip()
                if (
                    not value
                    or value in {'""', "''"}
                    or value.startswith("#")
                    or re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value)
                ):
                    continue
                findings.append(make_finding(
                    "HARDCODED_SECRET", f"заполненная переменная {match.group(1)}", relative, line_number, "medium"
                ))
    except (OSError, UnicodeError) as error:
        return [make_finding("SCAN_ERROR", f"не удалось прочитать env-файл: {error}", relative)]
    return findings


def yaml_secret_findings(path: Path, relative: str) -> list[Finding]:
    findings = []
    try:
        with path.open("r", encoding="utf-8-sig") as file:
            for line_number, text in enumerate(file, start=1):
                match = re.match(r"^\s*(?:-\s*)?([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*$", text)
                if not match:
                    match = re.match(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$", text)
                if not match or not is_secret_setting(match.group(1)):
                    continue
                value = match.group(2).strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                    value = value[1:-1].strip()
                if (
                    not value
                    or value.lower() in {"null", "~", "|", ">"}
                    or value.startswith(("#", "!"))
                    or re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value)
                    or re.fullmatch(r"\$\{\{\s*[^{}]+\s*\}\}", value)
                ):
                    continue
                findings.append(make_finding(
                    "HARDCODED_SECRET", f"строковое значение поля {match.group(1)}", relative, line_number, "medium"
                ))
    except (OSError, UnicodeError) as error:
        return [make_finding("SCAN_ERROR", f"не удалось прочитать YAML-файл: {error}", relative)]
    return findings


def private_key_findings(path: Path, relative: str) -> list[Finding]:
    try:
        with path.open("rb") as file:
            content = file.read(CONTENT_SCAN_BYTES)
    except OSError as error:
        return [make_finding("SCAN_ERROR", f"не удалось прочитать файл: {error}", relative)]

    findings = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        if PRIVATE_KEY_HEADER.fullmatch(line.strip()):
            findings.append(make_finding("PRIVATE_KEY_BLOCK", "найден заголовок приватного ключа", relative, line_number))
    return findings


def project_readiness_findings(files: list[Path], project: Path) -> list[Finding]:
    names = {path.relative_to(project).as_posix() for path in files}
    findings = []
    if not any(name.lower() in {"license", "license.md", "license.txt", "copying", "copying.md", "copying.txt"} for name in names):
        findings.append(make_finding("LICENSE", "файл лицензии не найден", confidence="medium"))
    if not any(name in CI_FILES or (name.startswith(".github/workflows/") and name.endswith((".yml", ".yaml"))) for name in names):
        findings.append(make_finding("CI", "конфигурация CI не найдена", confidence="medium"))
    if "package.json" in names and not names.intersection(NODE_LOCK_FILES):
        findings.append(make_finding("DEPENDENCY_LOCK", "для package.json не найден lock-файл", "package.json", confidence="medium"))
    for path in files:
        relative = path.relative_to(project).as_posix()
        if path.name not in {"requirements.txt", "requirements-dev.txt"}:
            continue
        try:
            with path.open("r", encoding="utf-8-sig") as file:
                for line_number, line in enumerate(file, 1):
                    item = line.strip()
                    if not item or item.startswith(("#", "-", ".")) or "://" in item:
                        continue
                    if re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[^]]+\])?\s*(?:[;#]|$|[<>=!~])", item) and "==" not in item and "===" not in item:
                        findings.append(make_finding("UNPINNED_DEPENDENCY", "зависимость без точной версии", relative, line_number, "medium"))
        except (OSError, UnicodeError) as error:
            findings.append(make_finding("SCAN_ERROR", f"не удалось прочитать зависимости: {error}", relative))
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


def staged_mismatch_findings(project: Path, excludes: tuple[str, ...]) -> list[Finding]:
    try:
        root = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True,
        )
        if root.returncode != 0 or Path(root.stdout.strip()).resolve() != project.resolve():
            return []
        staged = subprocess.run(
            ["git", "-C", str(project), "diff", "--cached", "--name-only", "-z", "--"],
            capture_output=True,
        )
        worktree = subprocess.run(
            ["git", "-C", str(project), "diff", "--name-only", "-z", "--"],
            capture_output=True,
        )
    except OSError:
        return []
    if staged.returncode != 0 or worktree.returncode != 0:
        return [make_finding("SCAN_ERROR", "не удалось сравнить подготовленные файлы с файлами на диске")]

    staged_paths = set(staged.stdout.split(b"\0"))
    worktree_paths = set(worktree.stdout.split(b"\0"))
    findings = []
    for raw_path in sorted((staged_paths & worktree_paths) - {b""}):
        relative = Path(os.fsdecode(raw_path)).as_posix()
        if any(part in IGNORED_DIRS for part in Path(relative).parts) or is_excluded(relative, excludes):
            continue
        findings.append(make_finding(
            "SCAN_ERROR", "подготовленная версия отличается от файла на диске; содержимое коммита не проверено", relative,
        ))
    return findings


def staged_files(project: Path, destination: Path) -> None:
    try:
        root = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True,
        )
        if root.returncode != 0 or Path(root.stdout.strip()).resolve() != project.resolve():
            raise ValueError("--staged требует корень Git-репозитория")
        entries = subprocess.run(
            ["git", "-C", str(project), "ls-files", "--stage", "-z"], capture_output=True,
        )
        if entries.returncode != 0:
            raise ValueError("не удалось получить список подготовленных файлов")
        for entry in entries.stdout.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            mode, blob_id, stage = metadata.split()
            if stage != b"0":
                raise ValueError("в Git index есть неразрешённые конфликты")
            relative = Path(os.fsdecode(raw_path))
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("в Git index найден недопустимый путь")
            if mode != b"100644" and mode != b"100755":
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as file:
                content = subprocess.run(
                    ["git", "-C", str(project), "cat-file", "blob", blob_id.decode("ascii")],
                    stdout=file, stderr=subprocess.PIPE,
                )
            if content.returncode != 0:
                raise ValueError(f"не удалось прочитать подготовленный файл: {relative.as_posix()}")
    except OSError as error:
        raise ValueError(f"не удалось прочитать Git index: {error}") from error


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
    findings.extend(staged_mismatch_findings(project, excludes))
    if not any((project / name).is_file() for name in ("README.md", "README.rst", "README.txt")):
        findings.append(make_finding("README", "добавьте описание проекта"))
    if not (project / ".gitignore").is_file():
        findings.append(make_finding("GITIGNORE", "добавьте .gitignore"))
    if not any(
        path.suffix == ".py" and (path.name.startswith("test_") or path.stem.endswith("_test"))
        for path in files
    ):
        findings.append(make_finding("TESTS", "тесты не найдены", confidence="low"))
    findings.extend(project_readiness_findings(files, project))

    for path in files:
        relative = path.relative_to(project).as_posix()
        findings.extend(private_key_findings(path, relative))
        if has_sensitive_name(path):
            findings.append(make_finding("SENSITIVE", "проверьте потенциально конфиденциальный файл", relative, confidence="medium"))
            if path.name.lower() == ".env" or path.name.lower().startswith(".env."):
                findings.extend(dotenv_secret_findings(path, relative))
        if path.name in {"settings.py", "config.py"}:
            findings.extend(python_secret_findings(path, relative))
        if path.name in CONFIG_FILE_NAMES:
            findings.extend(config_secret_findings(path, relative))
        if path.name in YAML_CONFIG_NAMES or relative in CI_FILES or (relative.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}):
            findings.extend(yaml_secret_findings(path, relative))
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
    parser.add_argument("--staged", action="store_true", help="проверить подготовленные к коммиту файлы")
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
