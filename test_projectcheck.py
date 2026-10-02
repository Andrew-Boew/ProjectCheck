from contextlib import redirect_stdout
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import projectcheck
from projectcheck import scan


class ScanTests(unittest.TestCase):
    def test_empty_project_has_five_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(len(scan(Path(directory))), 5)

    def test_complete_project_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "README.md").write_text("Project")
            (project / ".gitignore").write_text(".venv/\n")
            (project / "LICENSE").write_text("License\n")
            (project / ".gitlab-ci.yml").write_text("test: {}\n")
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

    def test_unreadable_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            target = project / "blocked.bin"
            target.write_bytes(b"data")
            original_stat = Path.stat

            def stat_with_error(path: Path, *args: object, **kwargs: object) -> object:
                if path == target:
                    raise PermissionError("access denied")
                return original_stat(path, *args, **kwargs)

            with patch("projectcheck.project_files", return_value=[target]), patch.object(Path, "stat", stat_with_error):
                findings = projectcheck.scan_details(project)
            self.assertIn(projectcheck.make_finding(
                "SCAN_ERROR", "не удалось получить размер файла: access denied", "blocked.bin"
            ), findings)

    def test_unreadable_directory_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            blocked = project / "private"

            def walk_with_error(root: Path, onerror: object) -> object:
                onerror(PermissionError(13, "Permission denied", str(blocked)))
                return iter(())

            with patch("projectcheck.git_project_files", return_value=None), patch(
                "projectcheck.os.walk", side_effect=walk_with_error
            ):
                findings = projectcheck.scan_details(project)
            self.assertIn(projectcheck.make_finding(
                "SCAN_ERROR", "не удалось прочитать папку: Permission denied", "private"
            ), findings)

    def test_scan_error_returns_two_without_fail_flag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            error = projectcheck.make_finding("SCAN_ERROR", "не удалось прочитать файл", "blocked.bin")
            with patch("projectcheck.scan_details", return_value=[error]), patch.object(
                sys, "argv", ["projectcheck.py", directory]
            ), redirect_stdout(io.StringIO()):
                self.assertEqual(projectcheck.main(), 2)

    def test_custom_size_limit_is_applied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            with (project / "archive.zip").open("wb") as file:
                file.truncate(2 * 1024 * 1024)
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--max-size-mib", "1"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("LARGE: файл больше 1 МиБ archive.zip", result.stdout)

    def test_size_limit_must_be_positive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--max-size-mib", "0"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--max-size-mib должен быть положительным числом", result.stderr)

    def test_config_applies_size_limit_and_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".projectcheck.toml").write_text('max_size_mib = 1\nexclude = ["*.bak"]\n')
            (project / "notes.bak").write_text("backup")
            with (project / "archive.zip").open("wb") as file:
                file.truncate(2 * 1024 * 1024)
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("LARGE: файл больше 1 МиБ archive.zip", result.stdout)
            self.assertNotIn("notes.bak", result.stdout)

    def test_cli_size_limit_overrides_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".projectcheck.toml").write_text("max_size_mib = 1\n")
            with (project / "archive.zip").open("wb") as file:
                file.truncate(2 * 1024 * 1024)
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--max-size-mib", "3"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertNotIn("LARGE:", result.stdout)

    def test_invalid_config_exits_with_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".projectcheck.toml").write_text("max_size_mib = 0\n")
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("max_size_mib должен быть положительным целым числом", result.stderr)

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

    def test_exclude_glob_skips_matching_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "notes.bak").write_text("temporary")
            (project / "keep.tmp").write_text("temporary")
            findings = scan(project, excludes=("*.bak",))
            self.assertNotIn("TEMP: временный файл notes.bak", findings)
            self.assertIn("TEMP: временный файл keep.tmp", findings)

    def test_exclude_directory_skips_its_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            generated = project / "generated"
            generated.mkdir()
            (generated / "cache.tmp").write_text("temporary")
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--exclude", "generated/"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertNotIn("cache.tmp", result.stdout)

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

    def test_private_key_header_is_found_inside_text_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            header = "-----BEGIN " + "PRIVATE KEY-----"
            (project / "notes.txt").write_text("heading\n" + header + "\nsecret-body\n")
            findings = scan(project)
            self.assertIn("PRIVATE_KEY_BLOCK: найден заголовок приватного ключа notes.txt:2", findings)
            self.assertFalse(any("secret-body" in item for item in findings))

    def test_public_key_header_is_not_reported_as_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            header = "-----BEGIN " + "PUBLIC KEY-----"
            (project / "public.pem").write_text(header + "\n")
            self.assertFalse(any(item.startswith("PRIVATE_KEY_BLOCK:") for item in scan(project)))

    def test_hardcoded_settings_are_reported_without_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "settings.py").write_text('SECRET_KEY = "private-example"\nPOSTGRES_PASSWORD: str = "demo"\n')
            findings = scan(project)
            self.assertIn("HARDCODED_SECRET: строковый литерал в SECRET_KEY settings.py:1", findings)
            self.assertIn("HARDCODED_SECRET: строковый литерал в POSTGRES_PASSWORD settings.py:2", findings)
            self.assertFalse(any("private-example" in item for item in findings))

    def test_environment_based_setting_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "config.py").write_text('import os\nSECRET_KEY = os.getenv("SECRET_KEY")\n')
            self.assertFalse(any(item.startswith("HARDCODED_SECRET:") for item in scan(project)))

    def test_nested_json_secret_is_reported_without_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "config.json").write_text('{"database": {"password": "private-example"}}')
            findings = scan(project)
            self.assertIn("HARDCODED_SECRET: строковое значение поля database.password config.json", findings)
            self.assertFalse(any("private-example" in item for item in findings))

    def test_toml_camel_case_secret_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "settings.toml").write_text('[auth]\napiToken = "example"\n')
            self.assertIn("HARDCODED_SECRET: строковое значение поля auth.apiToken settings.toml", scan(project))

    def test_non_secret_json_string_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "config.json").write_text('{"database": {"host": "localhost"}}')
            self.assertFalse(any(item.startswith("HARDCODED_SECRET:") for item in scan(project)))

    def test_environment_template_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".env.example").write_text("TOKEN=example\n")
            self.assertFalse(any(item.startswith("SENSITIVE:") for item in scan(project)))
            self.assertFalse(any(item.startswith("HARDCODED_SECRET:") for item in scan(project)))

    def test_dotenv_secret_is_reported_with_line_without_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".env").write_text('APP_NAME=demo\nexport API_TOKEN=private-example\nPASSWORD=\n')
            findings = scan(project)
            self.assertIn("HARDCODED_SECRET: заполненная переменная API_TOKEN .env:2", findings)
            self.assertFalse(any("private-example" in item for item in findings))
            self.assertFalse(any("PASSWORD" in item for item in findings))

    def test_dotenv_variable_reference_is_not_hardcoded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".env.local").write_text("API_TOKEN=${TOKEN_FROM_ENV}\n")
            self.assertFalse(any(item.startswith("HARDCODED_SECRET:") for item in scan(project)))

    def test_yaml_secret_is_reported_without_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "application.yaml").write_text('database:\n  password: "private-example"\n')
            findings = scan(project)
            self.assertIn("HARDCODED_SECRET: строковое значение поля password application.yaml:2", findings)
            self.assertFalse(any("private-example" in item for item in findings))

    def test_compose_environment_secret_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "compose.yml").write_text('services:\n  app:\n    environment:\n      - API_TOKEN=example\n')
            self.assertIn("HARDCODED_SECRET: строковое значение поля API_TOKEN compose.yml:4", scan(project))

    def test_yaml_environment_reference_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "config.yml").write_text('secret-key: "${SECRET_FROM_ENV}"\n')
            self.assertFalse(any(item.startswith("HARDCODED_SECRET:") for item in scan(project)))

    def test_gitignored_sensitive_file_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            (project / ".gitignore").write_text(".env\n")
            (project / ".env").write_text("TOKEN=example\n")
            self.assertFalse(any(item.startswith("SENSITIVE:") for item in scan(project)))

    def test_tracked_sensitive_file_is_reported_even_if_gitignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            (project / ".gitignore").write_text(".env\n")
            (project / ".env").write_text("TOKEN=example\n")
            subprocess.run(["git", "-C", directory, "add", "-f", ".env"], check=True)
            self.assertIn("SENSITIVE: проверьте потенциально конфиденциальный файл .env", scan(project))

    def test_staged_content_different_from_worktree_is_scan_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            config = project / "config.py"
            config.write_text('SECRET_KEY = "staged-value"\n')
            subprocess.run(["git", "-C", directory, "add", "config.py"], check=True)
            config.write_text('SECRET_KEY = os.getenv("SECRET_KEY")\n')

            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("SCAN_ERROR: подготовленная версия отличается от файла на диске; содержимое коммита не проверено config.py", result.stdout)
            self.assertNotIn("staged-value", result.stdout)

    def test_staged_mode_scans_index_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            (project / "README.md").write_text("Project\n")
            (project / ".gitignore").write_text("*.tmp\n")
            (project / "test_app.py").write_text("pass\n")
            (project / "LICENSE").write_text("License\n")
            (project / ".gitlab-ci.yml").write_text("test: {}\n")
            config = project / "config.py"
            config.write_text('SECRET_KEY = "staged-value"\n')
            subprocess.run(["git", "-C", directory, "add", "."], check=True)
            config.write_text('SECRET_KEY = os.getenv("SECRET_KEY")\n')

            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--staged", "--format", "json"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0)
            report = json.loads(result.stdout)
            self.assertEqual([item["code"] for item in report["findings"]], ["HARDCODED_SECRET"])
            self.assertEqual(report["findings"][0]["path"], "config.py")
            self.assertNotIn("staged-value", result.stdout)

    def test_project_readiness_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "package.json").write_text('{"name":"example"}\n')
            (project / "requirements.txt").write_text("requests>=2\nflask==3.0\n")
            findings = projectcheck.scan_details(project)
            self.assertIn("DEPENDENCY_LOCK", [item["code"] for item in findings])
            self.assertIn({
                "code": "UNPINNED_DEPENDENCY", "message": "зависимость без точной версии",
                "path": "requirements.txt", "line": 1, "confidence": "medium",
            }, findings)
            self.assertEqual(sum(item["code"] == "UNPINNED_DEPENDENCY" for item in findings), 1)

    def test_ci_workflow_secret_assignment_and_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            workflows = project / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "tests.yml").write_text(
                'env:\n  API_TOKEN: "literal-value"\n  DB_PASSWORD: ${{ secrets.DB_PASSWORD }}\n'
            )
            findings = projectcheck.scan_details(project)
            secret_findings = [item for item in findings if item["code"] == "HARDCODED_SECRET"]
            self.assertEqual(len(secret_findings), 1)
            self.assertEqual(secret_findings[0]["path"], ".github/workflows/tests.yml")
            self.assertEqual(secret_findings[0]["line"], 2)
            self.assertFalse(any(item["code"] == "CI" for item in findings))

    def test_installed_hook_blocks_security_but_allows_other_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            (project / "README.md").write_text("Project\n")
            (project / ".gitignore").write_text(".venv/\n")
            (project / "LICENSE").write_text("License\n")
            (project / ".gitlab-ci.yml").write_text("test: {}\n")
            (project / "test_app.py").write_text("pass\n")
            config = project / "config.py"
            config.write_text('API_TOKEN = "secret-value"\n')
            subprocess.run(["git", "-C", directory, "add", "."], check=True)

            hook = projectcheck.install_hook(project)
            self.assertEqual(hook.stat().st_mode & 0o111, 0o111)
            result = subprocess.run([hook], cwd=project, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("HARDCODED_SECRET", result.stdout)
            self.assertNotIn("secret-value", result.stdout)

            config.write_text('API_TOKEN = os.getenv("API_TOKEN")\n')
            subprocess.run(["git", "-C", directory, "add", "config.py"], check=True)
            result = subprocess.run([hook], cwd=project, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "Замечаний не найдено")
            subprocess.run(["git", "-C", directory, "rm", "--cached", "LICENSE"], check=True, capture_output=True)
            result = subprocess.run([hook], cwd=project, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn("LICENSE", result.stdout)
            strict = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--staged", "--fail-on-findings"],
                capture_output=True, text=True,
            )
            self.assertEqual(strict.returncode, 1)
            original = hook.read_text()
            self.assertEqual(projectcheck.install_hook(project), hook)
            hook.write_text(original.replace("--fail-on-security", "--fail-on-findings"))
            self.assertEqual(projectcheck.install_hook(project), hook)
            self.assertEqual(hook.read_text(), original)
            hook.write_text("#!/bin/sh\nexit 0\n")
            with self.assertRaisesRegex(ValueError, "уже существует"):
                projectcheck.install_hook(project)
            self.assertEqual(hook.read_text(), "#!/bin/sh\nexit 0\n")

    def test_versioned_hook_checks_staged_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            shutil.copy2(projectcheck.__file__, project / "projectcheck.py")
            hooks = project / ".githooks"
            hooks.mkdir()
            hook = hooks / "pre-commit"
            shutil.copy2(Path(projectcheck.__file__).parent / ".githooks" / "pre-commit", hook)
            (project / "README.md").write_text("Project\n")
            (project / ".gitignore").write_text(".venv/\n")
            (project / "LICENSE").write_text("License\n")
            (project / ".gitlab-ci.yml").write_text("test: {}\n")
            (project / "test_app.py").write_text("pass\n")
            config = project / "config.py"
            config.write_text('API_TOKEN = "staged-secret"\n')
            subprocess.run(["git", "-C", directory, "add", "."], check=True)
            config.write_text('API_TOKEN = os.getenv("API_TOKEN")\n')
            result = subprocess.run([hook], cwd=project, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("HARDCODED_SECRET", result.stdout)
            self.assertNotIn("staged-secret", result.stdout)

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
            self.assertEqual(report["count"], 5)
            self.assertEqual(len(report["findings"]), report["count"])
            self.assertEqual(report["findings"][0], {
                "code": "README", "message": "добавьте описание проекта", "path": None,
                "line": None, "confidence": "high",
            })

    def test_json_finding_has_relative_file_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".env").write_text("TOKEN=example\n")
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
            findings = json.loads(result.stdout)["findings"]
            self.assertIn({
                "code": "SENSITIVE",
                "message": "проверьте потенциально конфиденциальный файл",
                "path": ".env",
                "line": None,
                "confidence": "medium",
            }, findings)

    def test_json_secret_finding_has_line_and_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "settings.py").write_text('SECRET_KEY = "example"\n')
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
            findings = json.loads(result.stdout)["findings"]
            self.assertIn({
                "code": "HARDCODED_SECRET",
                "message": "строковый литерал в SECRET_KEY",
                "path": "settings.py",
                "line": 1,
                "confidence": "medium",
            }, findings)

    def test_fail_on_findings_returns_one_with_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--format", "json", "--fail-on-findings"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["count"], 5)

    def test_fail_on_findings_returns_zero_for_clean_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "README.md").write_text("Project")
            (project / ".gitignore").write_text(".venv/\n")
            (project / "test_example.py").write_text("pass\n")
            (project / "LICENSE").write_text("License\n")
            (project / ".gitlab-ci.yml").write_text("test: {}\n")
            result = subprocess.run(
                [sys.executable, projectcheck.__file__, directory, "--fail-on-findings"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Замечаний не найдено", result.stdout)


if __name__ == "__main__":
    unittest.main()
