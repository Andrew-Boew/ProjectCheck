import os
from pathlib import Path
import shlex
import subprocess
import sys

from constants import IGNORED_DIRS, is_excluded
from model.finding import Finding, make_finding


def _entry_script() -> Path:
    return Path(__file__).resolve().parents[1] / "projectcheck.py"


class GitWorkspace:
    def __init__(self, root: Path) -> None:
        self.root = root

    def repository_root(self) -> Path | None:
        top = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
        )
        if top.returncode != 0:
            return None
        found = Path(top.stdout.strip()).resolve()
        if found != self.root.resolve():
            return None
        return found

    def list_files(self, excludes: tuple[str, ...]) -> list[Path] | None:
        try:
            if self.repository_root() is None:
                return None
            result = subprocess.run(
                ["git", "-C", str(self.root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
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
            path = self.root / relative
            if (
                path.is_file()
                and not path.is_symlink()
                and not any(part in IGNORED_DIRS for part in Path(relative).parts)
                and not is_excluded(Path(relative).as_posix(), excludes)
            ):
                files.append(path)
        return sorted(files)

    def mismatch_findings(self, excludes: tuple[str, ...]) -> list[Finding]:
        try:
            if self.repository_root() is None:
                return []
            staged = subprocess.run(
                ["git", "-C", str(self.root), "diff", "--cached", "--name-only", "-z", "--"],
                capture_output=True,
            )
            worktree = subprocess.run(
                ["git", "-C", str(self.root), "diff", "--name-only", "-z", "--"],
                capture_output=True,
            )
        except OSError:
            return []
        if staged.returncode != 0 or worktree.returncode != 0:
            return [make_finding("SCAN_ERROR", "не удалось сравнить подготовленные файлы с файлами на диске")]

        staged_paths = set(staged.stdout.split(b"\0"))
        worktree_paths = set(worktree.stdout.split(b"\0"))
        findings: list[Finding] = []
        for raw_path in sorted((staged_paths & worktree_paths) - {b""}):
            relative = Path(os.fsdecode(raw_path)).as_posix()
            if any(part in IGNORED_DIRS for part in Path(relative).parts) or is_excluded(relative, excludes):
                continue
            findings.append(make_finding(
                "SCAN_ERROR", "подготовленная версия отличается от файла на диске; содержимое коммита не проверено", relative,
            ))
        return findings

    def export_staged(self, destination: Path) -> None:
        try:
            if self.repository_root() is None:
                raise ValueError("--staged требует корень Git-репозитория")
            entries = subprocess.run(
                ["git", "-C", str(self.root), "ls-files", "--stage", "-z"], capture_output=True,
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
                        ["git", "-C", str(self.root), "cat-file", "blob", blob_id.decode("ascii")],
                        stdout=file, stderr=subprocess.PIPE,
                    )
                if content.returncode != 0:
                    raise ValueError(f"не удалось прочитать подготовленный файл: {relative.as_posix()}")
        except OSError as error:
            raise ValueError(f"не удалось прочитать Git index: {error}") from error

    def install_hook(self) -> Path:
        try:
            if self.repository_root() is None:
                raise ValueError("установка hook требует корень Git-репозитория")
            configured = subprocess.run(
                ["git", "-C", str(self.root), "config", "--path", "--get", "core.hooksPath"],
                capture_output=True, text=True,
            )
            if configured.returncode == 0:
                hooks = Path(configured.stdout.strip())
                if not hooks.is_absolute():
                    hooks = self.root / hooks
            elif configured.returncode == 1:
                default = subprocess.run(
                    ["git", "-C", str(self.root), "rev-parse", "--git-path", "hooks"],
                    capture_output=True, text=True,
                )
                if default.returncode != 0:
                    raise ValueError("не удалось найти каталог Git hooks")
                hooks = Path(default.stdout.strip())
                if not hooks.is_absolute():
                    hooks = self.root / hooks
            else:
                raise ValueError("не удалось прочитать настройку core.hooksPath")
            hooks.mkdir(parents=True, exist_ok=True)
            hook = hooks / "pre-commit"
            base = f"exec {shlex.quote(sys.executable)} {shlex.quote(str(_entry_script()))} \"$repo_root\" --staged"
            prefix = '#!/bin/sh\nrepo_root=$(git rev-parse --show-toplevel) || exit 2\n'
            script = f"{prefix}{base} --fail-on-security\n"
            previous_script = f"{prefix}{base} --fail-on-findings\n"
            if hook.is_symlink():
                raise ValueError("pre-commit уже существует; существующий hook не изменён")
            if hook.exists():
                current = hook.read_bytes()
                if current == script.encode("utf-8"):
                    return hook
                if current != previous_script.encode("utf-8"):
                    raise ValueError("pre-commit уже существует; существующий hook не изменён")
                hook.write_text(script, encoding="utf-8")
            else:
                with hook.open("x", encoding="utf-8") as file:
                    file.write(script)
            hook.chmod(0o755)
            return hook
        except FileExistsError as error:
            raise ValueError("pre-commit уже существует; существующий hook не изменён") from error
        except OSError as error:
            raise ValueError(f"не удалось установить pre-commit: {error}") from error


def git_project_files(project: Path, excludes: tuple[str, ...]) -> list[Path] | None:
    return GitWorkspace(project).list_files(excludes)


def staged_mismatch_findings(project: Path, excludes: tuple[str, ...]) -> list[Finding]:
    return GitWorkspace(project).mismatch_findings(excludes)


def staged_files(project: Path, destination: Path) -> None:
    GitWorkspace(project).export_staged(destination)


def install_hook(project: Path) -> Path:
    return GitWorkspace(project).install_hook()
