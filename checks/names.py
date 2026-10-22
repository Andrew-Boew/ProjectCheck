from pathlib import Path


class SensitiveNames:
    PRIVATE_KEY_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
    ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template"}
    KEY_SUFFIXES = {".key", ".p12", ".pfx"}

    @staticmethod
    def matches(path: Path) -> bool:
        name = path.name.lower()
        return (
            (name == ".env" or name.startswith(".env.")) and name not in SensitiveNames.ENV_TEMPLATES
        ) or name in SensitiveNames.PRIVATE_KEY_NAMES or path.suffix.lower() in SensitiveNames.KEY_SUFFIXES


class CiCatalog:
    NAMES = {".gitlab-ci.yml", "azure-pipelines.yml", "Jenkinsfile", ".circleci/config.yml", ".travis.yml"}

    @staticmethod
    def matches(relative: str) -> bool:
        return relative in CiCatalog.NAMES or CiCatalog.is_workflow(relative, Path(relative).suffix)

    @staticmethod
    def is_workflow(relative: str, suffix: str) -> bool:
        return relative.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}
