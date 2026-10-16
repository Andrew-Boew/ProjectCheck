from pathlib import Path
import tomllib

from constants import DEFAULT_MAX_SIZE_MIB


class Settings:
    def __init__(self, max_size_mib: int = DEFAULT_MAX_SIZE_MIB, exclude: tuple[str, ...] = ()) -> None:
        self.max_size_mib = max_size_mib
        self.exclude = exclude

    @classmethod
    def load(cls, project: Path) -> "Settings":
        path = project / ".projectcheck.toml"
        if not path.exists():
            return cls()
        try:
            with path.open("rb") as file:
                config = tomllib.load(file)
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise ValueError(f"не удалось прочитать {path.name}: {error}") from error

        unknown = set(config) - {"max_size_mib", "exclude"}
        if unknown:
            raise ValueError(f"неизвестные настройки в {path.name}: {', '.join(sorted(unknown))}")
        max_size_mib = config.get("max_size_mib", DEFAULT_MAX_SIZE_MIB)
        excludes = config.get("exclude", [])
        if type(max_size_mib) is not int or max_size_mib <= 0:
            raise ValueError("max_size_mib должен быть положительным целым числом")
        if not isinstance(excludes, list) or any(not isinstance(pattern, str) or not pattern for pattern in excludes):
            raise ValueError("exclude должен быть списком непустых строк")
        return cls(max_size_mib, tuple(excludes))
