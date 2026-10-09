from pathlib import Path

from constants import IGNORED_DIRS, is_excluded
from model.finding import Finding, make_finding


class ProjectFiles:
    def __init__(self, root: Path, exclude: tuple[str, ...] = ()) -> None:
        self.root = root
        self.exclude = exclude
        self.git: object | None = None

    def is_excluded(self, relative: str) -> bool:
        return is_excluded(relative, self.exclude)

    def collect(self, errors: list[Finding] | None = None) -> list[Path]:
        import projectcheck
        from workspace.git import GitWorkspace

        listed = projectcheck.git_project_files(self.root, self.exclude)
        if listed is not None:
            self.git = GitWorkspace(self.root)
            return listed

        def on_walk_error(error: OSError) -> None:
            relative = None
            if error.filename:
                try:
                    relative = Path(error.filename).resolve().relative_to(self.root.resolve()).as_posix()
                except ValueError:
                    pass
            if errors is not None:
                errors.append(make_finding("SCAN_ERROR", f"не удалось прочитать папку: {error.strerror or error}", relative))

        files = []
        for directory, subdirs, names in projectcheck.os.walk(self.root, onerror=on_walk_error):
            subdirs[:] = sorted(
                name for name in subdirs
                if name not in IGNORED_DIRS
                and not (Path(directory) / name).is_symlink()
                and not self.is_excluded((Path(directory) / name).relative_to(self.root).as_posix())
            )
            for name in sorted(names):
                path = Path(directory) / name
                if path.is_file() and not path.is_symlink() and not self.is_excluded(path.relative_to(self.root).as_posix()):
                    files.append(path)
        return files


def project_files(project: Path, excludes: tuple[str, ...] = (), errors: list[Finding] | None = None) -> list[Path]:
    return ProjectFiles(project, excludes).collect(errors)
