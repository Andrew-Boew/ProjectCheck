from abc import ABC, abstractmethod
import ast
import json
from pathlib import Path
import re
import tomllib
import tokenize

from constants import CONFIG_FILE_NAMES, CI_FILES, YAML_CONFIG_NAMES, has_sensitive_name, is_secret_setting
from model.finding import Finding, make_finding


class SecretParser(ABC):
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
            return [make_finding("SCAN_ERROR", f"не удалось прочитать Python-файл: {error}", relative)]

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
                if isinstance(target, ast.Name) and is_secret_setting(target.id):
                    findings.append(make_finding(
                        "HARDCODED_SECRET", f"строковый литерал в {target.id}", relative, node.lineno, "medium"
                    ))
        return findings


class ConfigSecretParser(SecretParser):
    def parse(self, path: Path, relative: str) -> list[Finding]:
        if path.name not in CONFIG_FILE_NAMES:
            return []
        try:
            if path.suffix == ".json":
                with path.open("r", encoding="utf-8-sig") as file:
                    data = json.load(file)
            else:
                with path.open("rb") as file:
                    data = tomllib.load(file)
        except (OSError, UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
            return [make_finding("SCAN_ERROR", f"не удалось разобрать конфигурацию: {error}", relative)]

        findings: list[Finding] = []

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


class DotenvSecretParser(SecretParser):
    def parse(self, path: Path, relative: str) -> list[Finding]:
        if not has_sensitive_name(path) or not (path.name.lower() == ".env" or path.name.lower().startswith(".env.")):
            return []
        findings: list[Finding] = []
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


class YamlSecretParser(SecretParser):
    def parse(self, path: Path, relative: str) -> list[Finding]:
        if path.name not in YAML_CONFIG_NAMES and relative not in CI_FILES and not (
            relative.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}
        ):
            return []
        findings: list[Finding] = []
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
