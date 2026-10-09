class Finding:
    def __init__(
        self,
        code: str,
        message: str,
        path: str | None = None,
        line: int | None = None,
        confidence: str = "high",
    ) -> None:
        self.code = code
        self.message = message
        self.path = path
        self.line = line
        self.confidence = confidence

    def as_dict(self) -> dict[str, str | int | None]:
        return {
            "code": self.code,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "confidence": self.confidence,
        }

    def __getitem__(self, key: str) -> str | int | None:
        return self.as_dict()[key]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Finding):
            return self.as_dict() == other.as_dict()
        if isinstance(other, dict):
            return self.as_dict() == other
        return NotImplemented


def make_finding(code: str, message: str, path: str | None = None, line: int | None = None, confidence: str = "high") -> Finding:
    return Finding(code, message, path, line, confidence)


def format_finding(item: Finding) -> str:
    path = f" {item['path']}" if item["path"] else ""
    if path and item["line"] is not None:
        path += f":{item['line']}"
    return f"{item['code']}: {item['message']}{path}"
