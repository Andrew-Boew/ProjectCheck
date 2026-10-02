import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import projectcheck
from projectcheck import scan


class ScanTests(unittest.TestCase):
    def test_empty_project_has_three_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(len(scan(Path(directory))), 3)

    def test_complete_project_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "README.md").write_text("Project")
            (project / ".gitignore").write_text(".venv/\n")
            tests = project / "tests"
            tests.mkdir()
            (tests / "test_example.py").write_text("def test_example(): pass\n")
            self.assertEqual(scan(project), [])

    def test_venv_tests_do_not_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            venv = project / ".venv"
            venv.mkdir()
            (venv / "test_dependency.py").write_text("pass\n")
            self.assertTrue(any(item.startswith("TESTS:") for item in scan(project)))

    def test_large_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            with (project / "video.mov").open("wb") as file:
                file.truncate(10 * 1024 * 1024 + 1)
            self.assertIn("LARGE: файл больше 10 МиБ video.mov", scan(project))

    def test_temporary_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "notes.txt.bak").write_text("backup")
            self.assertIn("TEMP: временный файл notes.txt.bak", scan(project))

    def test_ignored_directory_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            cache = project / "node_modules"
            cache.mkdir()
            (cache / "artifact.tmp").write_text("generated")
            self.assertFalse(any(item.startswith("TEMP:") for item in scan(project)))

    def test_sensitive_file_names_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".env.local").write_text("TOKEN=example\n")
            keys = project / "keys"
            keys.mkdir()
            (keys / "id_ed25519").write_text("example\n")
            findings = scan(project)
            self.assertIn("SENSITIVE: проверьте потенциально конфиденциальный файл .env.local", findings)
            self.assertIn("SENSITIVE: проверьте потенциально конфиденциальный файл keys/id_ed25519", findings)

    def test_environment_template_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".env.example").write_text("TOKEN=\n")
            self.assertFalse(any(item.startswith("SENSITIVE:") for item in scan(project)))

    def test_json_report_contains_findings_and_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
            report = json.loads(result.stdout)
            self.assertEqual(report["project"], str(Path(directory).resolve()))
            self.assertEqual(report["count"], 3)
            self.assertEqual(len(report["findings"]), report["count"])


if __name__ == "__main__":
    unittest.main()
