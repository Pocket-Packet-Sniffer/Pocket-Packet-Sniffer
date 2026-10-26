"""Stable, actionable errors raised by Capture Layer backends."""


class CaptureError(Exception):
    """Base error that the CLI/application can report without a traceback."""


class CaptureInterfaceError(CaptureError):
    """The selected capture interface does not exist or is unavailable."""


class CapturePermissionError(CaptureError):
    """The current process lacks operating-system capture permissions."""


class CaptureBackendUnavailableError(CaptureError):
    """A requested capture backend or its optional dependency is unavailable."""


class CaptureFileError(CaptureError):
    """A PCAP input file is missing, malformed, or unreadable."""


class CaptureStartupError(CaptureError):
    """A capture backend failed during initialization or startup."""


class CaptureCallbackError(CaptureError):
    """The next layer failed while processing a captured packet callback."""
