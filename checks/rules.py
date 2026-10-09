from abc import ABC, abstractmethod
from pathlib import Path
import re

from constants import (
    CI_FILES,
    CONTENT_SCAN_BYTES,
    NODE_LOCK_FILES,
    PRIVATE_KEY_HEADER,
    TEMP_SUFFIXES,
    has_sensitive_name,
)
from model.finding import Finding, make_finding
from parsers.secrets import (
    ConfigSecretParser,
    DotenvSecretParser,
    PythonSecretParser,
    SecretParser,
    YamlSecretParser,
)


class Check(ABC):
    each_file = False

    @abstractmethod
    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        raise NotImplementedError


class ProjectLevelCheck(Check):
    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        names = {path.relative_to(project).as_posix() for path in files}
        findings: list[Finding] = []
        if not any((project / name).is_file() for name in ("README.md", "README.rst", "README.txt")):
            findings.append(make_finding("README", "добавьте описание проекта"))
        if not (project / ".gitignore").is_file():
            findings.append(make_finding("GITIGNORE", "добавьте .gitignore"))
        if not any(
            path.suffix == ".py" and (path.name.startswith("test_") or path.stem.endswith("_test"))
            for path in files
        ):
            findings.append(make_finding("TESTS", "тесты не найдены", confidence="low"))
        if not any(name.lower() in {"license", "license.md", "license.txt", "copying", "copying.md", "copying.txt"} for name in names):
            findings.append(make_finding("LICENSE", "файл лицензии не найден", confidence="medium"))
        if not any(name in CI_FILES or (name.startswith(".github/workflows/") and name.endswith((".yml", ".yaml"))) for name in names):
            findings.append(make_finding("CI", "конфигурация CI не найдена", confidence="medium"))
        return findings


class SensitiveCheck(Check):
    each_file = True

    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            if has_sensitive_name(path):
                relative = path.relative_to(project).as_posix()
                findings.append(make_finding("SENSITIVE", "проверьте потенциально конфиденциальный файл", relative, confidence="medium"))
        return findings


class FileCheck(Check):
    each_file = True

    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            relative = path.relative_to(project).as_posix()
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


class PrivateKeyCheck(Check):
    each_file = True

    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            relative = path.relative_to(project).as_posix()
            try:
                with path.open("rb") as file:
                    content = file.read(CONTENT_SCAN_BYTES)
            except OSError as error:
                findings.append(make_finding("SCAN_ERROR", f"не удалось прочитать файл: {error}", relative))
                continue
            for line_number, line in enumerate(content.splitlines(), start=1):
                if PRIVATE_KEY_HEADER.fullmatch(line.strip()):
                    findings.append(make_finding("PRIVATE_KEY_BLOCK", "найден заголовок приватного ключа", relative, line_number))
        return findings


class SecretCheck(Check):
    each_file = True

    def __init__(self, parsers: tuple[SecretParser, ...] | None = None) -> None:
        self.parsers = parsers or (
            DotenvSecretParser(),
            PythonSecretParser(),
            ConfigSecretParser(),
            YamlSecretParser(),
        )

    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            relative = path.relative_to(project).as_posix()
            for parser in self.parsers:
                findings.extend(parser.parse(path, relative))
        return findings


class DependencyCheck(Check):
    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        names = {path.relative_to(project).as_posix() for path in files}
        findings: list[Finding] = []
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


def default_checks() -> tuple[Check, ...]:
    return (
        ProjectLevelCheck(),
        DependencyCheck(),
        PrivateKeyCheck(),
        SensitiveCheck(),
        SecretCheck(),
        FileCheck(),
    )
