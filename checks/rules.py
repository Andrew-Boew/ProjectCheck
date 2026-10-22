from abc import ABC, abstractmethod
from pathlib import Path
import re

from checks.names import CiCatalog, SensitiveNames
from model.finding import Finding
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

    @classmethod
    def defaults(cls) -> tuple["Check", ...]:
        return (
            ProjectLevelCheck(),
            DependencyCheck(),
            PrivateKeyCheck(),
            SensitiveCheck(),
            SecretCheck(),
            FileCheck(),
        )


class ProjectLevelCheck(Check):
    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        names = {path.relative_to(project).as_posix() for path in files}
        findings: list[Finding] = []
        if not any((project / name).is_file() for name in ("README.md", "README.rst", "README.txt")):
            findings.append(Finding("README", "добавьте описание проекта"))
        if not (project / ".gitignore").is_file():
            findings.append(Finding("GITIGNORE", "добавьте .gitignore"))
        if not any(
            path.suffix == ".py" and (path.name.startswith("test_") or path.stem.endswith("_test"))
            for path in files
        ):
            findings.append(Finding("TESTS", "тесты не найдены", confidence="low"))
        if not any(name.lower() in {"license", "license.md", "license.txt", "copying", "copying.md", "copying.txt"} for name in names):
            findings.append(Finding("LICENSE", "файл лицензии не найден", confidence="medium"))
        if not any(CiCatalog.matches(name) for name in names):
            findings.append(Finding("CI", "конфигурация CI не найдена", confidence="medium"))
        return findings


class SensitiveCheck(Check):
    each_file = True

    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            if SensitiveNames.matches(path):
                relative = path.relative_to(project).as_posix()
                findings.append(Finding("SENSITIVE", "проверьте потенциально конфиденциальный файл", relative, confidence="medium"))
        return findings


class FileCheck(Check):
    each_file = True
    TEMP_SUFFIXES = {".tmp", ".bak", ".swp", ".swo"}

    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            relative = path.relative_to(project).as_posix()
            if path.suffix.lower() in self.TEMP_SUFFIXES or path.name.endswith("~") or path.name == ".DS_Store":
                findings.append(Finding("TEMP", "временный файл", relative, confidence="medium"))
            try:
                size = path.stat().st_size
            except OSError as error:
                findings.append(Finding("SCAN_ERROR", f"не удалось получить размер файла: {error}", relative))
                continue
            if size > max_size_mib * 1024 * 1024:
                findings.append(Finding("LARGE", f"файл больше {max_size_mib} МиБ", relative))
        return findings


class PrivateKeyCheck(Check):
    each_file = True
    SCAN_BYTES = 2 * 1024 * 1024
    HEADER = re.compile(rb"^-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----$")

    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            relative = path.relative_to(project).as_posix()
            try:
                with path.open("rb") as file:
                    content = file.read(self.SCAN_BYTES)
            except OSError as error:
                findings.append(Finding("SCAN_ERROR", f"не удалось прочитать файл: {error}", relative))
                continue
            for line_number, line in enumerate(content.splitlines(), start=1):
                if self.HEADER.fullmatch(line.strip()):
                    findings.append(Finding("PRIVATE_KEY_BLOCK", "найден заголовок приватного ключа", relative, line_number))
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
    LOCK_FILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}

    def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list[Finding]:
        names = {path.relative_to(project).as_posix() for path in files}
        findings: list[Finding] = []
        if "package.json" in names and not names.intersection(self.LOCK_FILES):
            findings.append(Finding("DEPENDENCY_LOCK", "для package.json не найден lock-файл", "package.json", confidence="medium"))
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
                            findings.append(Finding("UNPINNED_DEPENDENCY", "зависимость без точной версии", relative, line_number, "medium"))
            except (OSError, UnicodeError) as error:
                findings.append(Finding("SCAN_ERROR", f"не удалось прочитать зависимости: {error}", relative))
        return findings
