from __future__ import annotations

from typing import Any


class ReportGenerationError(Exception):
    """Base class for report generation failures."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "report_error",
        path: str | None = None,
        line_no: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.code = code
        self.path = path
        self.line_no = line_no
        self.details = details or {}
        super().__init__(self.__str__())

    def __str__(self) -> str:
        parts = [self.message]
        if self.path:
            parts.append(f"path={self.path}")
        if self.line_no is not None:
            parts.append(f"line={self.line_no}")
        if self.code:
            parts.append(f"code={self.code}")
        return " | ".join(parts)


class ReportIOError(ReportGenerationError):
    """File system or streaming errors."""

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message,
            code="report_io_error",
            path=path,
            details=details,
        )


class ReportFormatError(ReportGenerationError):
    """Malformed findings or summary data."""

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        line_no: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message,
            code="report_format_error",
            path=path,
            line_no=line_no,
            details=details,
        )


class ReportRenderError(ReportGenerationError):
    """Template/rendering failures while building final output artifacts."""

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message,
            code="report_render_error",
            path=path,
            details=details,
        )
