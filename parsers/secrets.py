from abc import ABC, abstractmethod
import ast
import json
from pathlib import Path
import re
import tomllib
import tokenize

from checks.names import CiCatalog, SensitiveNames
from model.finding import Finding


class SecretParser(ABC):
    SUFFIXES = ("SECRET", "SECRET_KEY", "PASSWORD", "TOKEN", "API_KEY", "PRIVATE_KEY", "CREDENTIAL", "CREDENTIALS")

    @staticmethod
    def looks_secret(name: str) -> bool:
        upper = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).replace("-", "_").upper()
        return any(upper == suffix or upper.endswith(f"_{suffix}") for suffix in SecretParser.SUFFIXES)

    @abstractmethod
    def parse(self, path: Path, relative: str) -> list[Finding]:
        raise NotImplementedError


class PythonSecretParser(SecretParser):
    def parse(self, path: Path, relative: str) -> list[Finding]:
        if path.name not in {"settings.py", "config.py"}:
            return []
        try:
            with tokenize.open(path) as file:
                tree = ast.parse(file.read(), filename=relative)
        except SyntaxError:
            return []
        except (OSError, UnicodeError) as error:
            return [Finding("SCAN_ERROR", f"не удалось прочитать Python-файл: {error}", relative)]

        findings: list[Finding] = []
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
                if isinstance(target, ast.Name) and self.looks_secret(target.id):
                    findings.append(Finding(
                        "HARDCODED_SECRET", f"строковый литерал в {target.id}", relative, node.lineno, "medium"
                    ))
        return findings


class ConfigSecretParser(SecretParser):
    NAMES = {"settings.json", "config.json", "appsettings.json", "settings.toml", "config.toml", "pyproject.toml"}

    def parse(self, path: Path, relative: str) -> list[Finding]:
        if path.name not in self.NAMES:
            return []
        try:
            if path.suffix == ".json":
                with path.open("r", encoding="utf-8-sig") as file:
                    data = json.load(file)
            else:
                with path.open("rb") as file:
                    data = tomllib.load(file)
        except (OSError, UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
            return [Finding("SCAN_ERROR", f"не удалось разобрать конфигурацию: {error}", relative)]

        findings: list[Finding] = []
        self.walk(data, findings, relative)
        return findings

    def walk(self, value: object, findings: list[Finding], relative: str, key_path: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{key_path}.{key}" if key_path else str(key)
                if isinstance(child, str) and child.strip() and self.looks_secret(str(key)):
                    findings.append(Finding(
                        "HARDCODED_SECRET", f"строковое значение поля {child_path}", relative, confidence="medium"
                    ))
                else:
                    self.walk(child, findings, relative, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                self.walk(child, findings, relative, f"{key_path}[{index}]")


class DotenvSecretParser(SecretParser):
    def parse(self, path: Path, relative: str) -> list[Finding]:
        if not SensitiveNames.matches(path) or not (path.name.lower() == ".env" or path.name.lower().startswith(".env.")):
            return []
        findings: list[Finding] = []
        try:
            with path.open("r", encoding="utf-8-sig") as file:
                for line_number, text in enumerate(file, start=1):
                    match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", text)
                    if not match or not self.looks_secret(match.group(1)):
                        continue
                    value = match.group(2).strip()
                    if (
                        not value
                        or value in {'""', "''"}
                        or value.startswith("#")
                        or re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value)
                    ):
                        continue
                    findings.append(Finding(
                        "HARDCODED_SECRET", f"заполненная переменная {match.group(1)}", relative, line_number, "medium"
                    ))
        except (OSError, UnicodeError) as error:
            return [Finding("SCAN_ERROR", f"не удалось прочитать env-файл: {error}", relative)]
        return findings


class YamlSecretParser(SecretParser):
    NAMES = {
        "settings.yml", "settings.yaml", "config.yml", "config.yaml", "application.yml", "application.yaml",
        "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "values.yml", "values.yaml",
    }

    def parse(self, path: Path, relative: str) -> list[Finding]:
        if path.name not in self.NAMES and not CiCatalog.matches(relative):
            return []
        findings: list[Finding] = []
        try:
            with path.open("r", encoding="utf-8-sig") as file:
                for line_number, text in enumerate(file, start=1):
                    match = re.match(r"^\s*(?:-\s*)?([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*$", text)
                    if not match:
                        match = re.match(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$", text)
                    if not match or not self.looks_secret(match.group(1)):
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
                    findings.append(Finding(
                        "HARDCODED_SECRET", f"строковое значение поля {match.group(1)}", relative, line_number, "medium"
                    ))
        except (OSError, UnicodeError) as error:
            return [Finding("SCAN_ERROR", f"не удалось прочитать YAML-файл: {error}", relative)]
        return findings
