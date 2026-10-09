from fnmatch import fnmatchcase
from pathlib import Path
import re

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
DEFAULT_MAX_SIZE_MIB = 10
SECURITY_CODES = {"SENSITIVE", "HARDCODED_SECRET", "PRIVATE_KEY_BLOCK"}
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


def has_sensitive_name(path: Path) -> bool:
    name = path.name.lower()
    return (
        (name == ".env" or name.startswith(".env.")) and name not in ENV_TEMPLATES
    ) or name in PRIVATE_KEY_NAMES or path.suffix.lower() in {".key", ".p12", ".pfx"}


def is_secret_setting(name: str) -> bool:
    upper = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).replace("-", "_").upper()
    return any(upper == suffix or upper.endswith(f"_{suffix}") for suffix in SECRET_SETTING_SUFFIXES)


def is_excluded(relative: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/"):
            if relative == pattern.rstrip("/") or relative.startswith(pattern):
                return True
        elif fnmatchcase(relative, pattern):
            return True
    return False
