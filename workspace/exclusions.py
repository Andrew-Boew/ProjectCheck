from fnmatch import fnmatchcase


class Exclusions:
    IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}

    def __init__(self, patterns: tuple[str, ...] = ()) -> None:
        self.patterns = patterns

    def matches(self, relative: str) -> bool:
        for pattern in self.patterns:
            if pattern.endswith("/"):
                if relative == pattern.rstrip("/") or relative.startswith(pattern):
                    return True
            elif fnmatchcase(relative, pattern):
                return True
        return False

    def skips_directory(self, name: str) -> bool:
        return name in self.IGNORED_DIRS
