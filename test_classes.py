import json
import tempfile
import unittest
from pathlib import Path

from checks.rules import Check, FileCheck, ProjectLevelCheck
from model.finding import make_finding
from model.report import Report
from model.settings import Settings
from parsers.secrets import PythonSecretParser
from scanner import Scanner
from workspace.files import ProjectFiles
from workspace.git import GitWorkspace


class FindingTests(unittest.TestCase):
    def test_finding_keeps_fields_and_matches_dict(self) -> None:
        item = make_finding("LARGE", "файл больше 10 МиБ", "video.mov", confidence="high")
        self.assertEqual(item["code"], "LARGE")
        self.assertEqual(item["line"], None)
        self.assertEqual(item.as_dict(), {
            "code": "LARGE",
            "message": "файл больше 10 МиБ",
            "path": "video.mov",
            "line": None,
            "confidence": "high",
        })
        self.assertEqual(item, item.as_dict())


class SettingsTests(unittest.TestCase):
    def test_missing_config_uses_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings.load(Path(directory))
        self.assertEqual(settings.max_size_mib, 10)
        self.assertEqual(settings.exclude, ())

    def test_load_reads_threshold_and_exclude(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".projectcheck.toml").write_text('max_size_mib = 1\nexclude = ["*.bak"]\n')
            settings = Settings.load(project)
        self.assertEqual(settings.max_size_mib, 1)
        self.assertEqual(settings.exclude, ("*.bak",))

    def test_load_rejects_non_positive_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".projectcheck.toml").write_text("max_size_mib = 0\n")
            with self.assertRaisesRegex(ValueError, "положительным целым"):
                Settings.load(project)


class ReportTests(unittest.TestCase):
    def test_exit_code_follows_scan_error_and_flags(self) -> None:
        error = make_finding("SCAN_ERROR", "не удалось прочитать файл", "blocked.bin")
        readme = make_finding("README", "добавьте описание проекта")
        secret = make_finding("SENSITIVE", "проверьте потенциально конфиденциальный файл", ".env", confidence="medium")
        self.assertEqual(Report([error], "text").exit_code(), 2)
        self.assertEqual(Report([readme], "text").exit_code(fail_on_findings=True), 1)
        self.assertEqual(Report([readme], "text").exit_code(fail_on_security=True), 0)
        self.assertEqual(Report([secret], "text").exit_code(fail_on_security=True), 1)
        self.assertEqual(Report([], "text").exit_code(fail_on_findings=True), 0)

    def test_render_text_and_json(self) -> None:
        project = Path("/tmp/sample")
        empty = Report([], "text").render(project)
        self.assertEqual(empty, "Замечаний не найдено")
        report = Report([make_finding("README", "добавьте описание проекта")], "json")
        payload = json.loads(report.render(project))
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["findings"][0]["code"], "README")
        self.assertEqual(payload["project"], str(project))


class CheckTests(unittest.TestCase):
    def test_project_level_check_on_empty_and_complete_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            empty = ProjectLevelCheck().apply(project, [], 10)
            self.assertEqual(
                [item["code"] for item in empty],
                ["README", "GITIGNORE", "TESTS", "LICENSE", "CI"],
            )
            (project / "README.md").write_text("Project\n")
            (project / ".gitignore").write_text(".venv/\n")
            (project / "LICENSE").write_text("License\n")
            (project / ".gitlab-ci.yml").write_text("test: {}\n")
            tests = project / "tests"
            tests.mkdir()
            example = tests / "test_example.py"
            example.write_text("def test_example(): pass\n")
            files = [project / "LICENSE", project / ".gitlab-ci.yml", example]
            self.assertEqual(ProjectLevelCheck().apply(project, files, 10), [])

    def test_file_check_reports_temp_and_large(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            temp = project / "notes.txt.bak"
            temp.write_text("x")
            large = project / "video.mov"
            with large.open("wb") as file:
                file.truncate(10 * 1024 * 1024 + 1)
            findings = FileCheck().apply(project, [temp, large], 10)
            codes = [item["code"] for item in findings]
            self.assertEqual(codes, ["TEMP", "LARGE"])
            self.assertEqual(findings[1]["path"], "video.mov")


class ParserTests(unittest.TestCase):
    def test_python_parser_reads_secret_and_skips_other_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            settings = project / "settings.py"
            settings.write_text('SECRET_KEY = "example"\n')
            other = project / "app.py"
            other.write_text('SECRET_KEY = "example"\n')
            parser = PythonSecretParser()
            found = parser.parse(settings, "settings.py")
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["code"], "HARDCODED_SECRET")
            self.assertEqual(found[0]["line"], 1)
            self.assertEqual(parser.parse(other, "app.py"), [])


class WorkspaceTests(unittest.TestCase):
    def test_collect_skips_venv_and_exclude_outside_git(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            venv = project / ".venv"
            venv.mkdir()
            (venv / "test_dependency.py").write_text("pass\n")
            (project / "keep.txt").write_text("ok")
            (project / "skip.bak").write_text("no")
            files = ProjectFiles(project, ("*.bak",))
            listed = files.collect()
            names = {path.name for path in listed}
            self.assertEqual(names, {"keep.txt"})
            self.assertIsNone(files.git)
            self.assertIsNone(GitWorkspace(project).repository_root())


class ScannerTests(unittest.TestCase):
    def test_scanner_runs_checks_in_list_order(self) -> None:
        class WholeProject(Check):
            def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list:
                return [make_finding("README", "сначала проект")]

        class OneFile(Check):
            each_file = True

            def apply(self, project: Path, files: list[Path], max_size_mib: int) -> list:
                return [make_finding("TEMP", "потом файл", files[0].name)]

        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "a.txt").write_text("x")
            findings = Scanner(Settings(), checks=(WholeProject(), OneFile())).run(project)
        self.assertEqual([item["code"] for item in findings], ["README", "TEMP"])

    def test_scanner_on_empty_directory_returns_five_project_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            findings = Scanner(Settings()).run(Path(directory))
        self.assertEqual(
            [item["code"] for item in findings],
            ["README", "GITIGNORE", "TESTS", "LICENSE", "CI"],
        )
