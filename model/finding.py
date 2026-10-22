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
