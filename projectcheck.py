import argparse
from pathlib import Path


def scan(project: Path) -> list[str]:
    findings = []
    if not any((project / name).is_file() for name in ("README.md", "README.rst", "README.txt")):
        findings.append("README: добавьте описание проекта")
    if not (project / ".gitignore").is_file():
        findings.append("GITIGNORE: добавьте .gitignore")
    if not any(
        path.is_file()
        for pattern in ("test_*.py", "*_test.py")
        for path in project.rglob(pattern)
        if not any(part in {".git", ".venv", "venv", "node_modules"} for part in path.relative_to(project).parts)
    ):
        findings.append("TESTS: тесты не найдены")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка локального проекта")
    parser.add_argument("project", type=Path, help="путь к проекту")
    args = parser.parse_args()

    project = args.project.expanduser().resolve()
    if not project.is_dir():
        parser.error(f"папка не найдена: {project}")

    findings = scan(project)
    if findings:
        for finding in findings:
            print(f"- {finding}")
        print(f"Найдено замечаний: {len(findings)}")
    else:
        print("Замечаний не найдено")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
