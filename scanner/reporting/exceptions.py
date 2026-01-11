class ReportGenerationError(Exception):
    """Base class for report generation failures."""


class ReportIOError(ReportGenerationError):
    """File system or streaming errors."""


class ReportFormatError(ReportGenerationError):
    """Malformed findings or summary data."""
