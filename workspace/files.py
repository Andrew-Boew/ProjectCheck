import os
from pathlib import Path

from model.finding import Finding
from workspace.exclusions import Exclusions
from workspace.git import GitWorkspace


class ProjectFiles:
    def __init__(self, root: Path, exclusions: Exclusions | None = None) -> None:
        self.root = root
        self.exclusions = exclusions or Exclusions()
        self.git: GitWorkspace | None = None
        self.errors: list[Finding] | None = None

    def collect(self, errors: list[Finding] | None = None) -> list[Path]:
        workspace = GitWorkspace(self.root)
        listed = workspace.list_files(self.exclusions)
        if listed is not None:
            self.git = workspace
            return listed

        self.errors = errors
        files = []
        for directory, subdirs, names in os.walk(self.root, onerror=self.remember_walk_error):
            subdirs[:] = sorted(
                name for name in subdirs
                if not self.exclusions.skips_directory(name)
                and not (Path(directory) / name).is_symlink()
                and not self.exclusions.matches((Path(directory) / name).relative_to(self.root).as_posix())
            )
            for name in sorted(names):
                path = Path(directory) / name
                if path.is_file() and not path.is_symlink() and not self.exclusions.matches(path.relative_to(self.root).as_posix()):
                    files.append(path)
        return files

    def remember_walk_error(self, error: OSError) -> None:
        relative = None
        if error.filename:
            try:
                relative = Path(error.filename).resolve().relative_to(self.root.resolve()).as_posix()
            except ValueError:
                pass
        if self.errors is not None:
            self.errors.append(Finding("SCAN_ERROR", f"не удалось прочитать папку: {error.strerror or error}", relative))
