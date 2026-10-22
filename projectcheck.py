from application import Application, CommandLine


def main() -> int:
    return Application(CommandLine()).run()


if __name__ == "__main__":
    raise SystemExit(main())
