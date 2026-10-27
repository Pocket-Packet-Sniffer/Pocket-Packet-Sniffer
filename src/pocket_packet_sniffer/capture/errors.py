"""Stable, actionable errors raised by Capture Layer backends."""

from __future__ import annotations


def _callback_failure_detail(exc: Exception) -> str:
    """Return safe diagnostic context for an exception raised by a packet callback.

    Project-owned exceptions use sanitized domain messages. Arbitrary callback
    exceptions expose only their type so custom code cannot accidentally print
    captured data to the terminal.
    """
    error_type = type(exc)
    name = error_type.__name__
    if error_type.__module__.startswith("pocket_packet_sniffer."):
        detail = " ".join(str(exc).split())[:240]
        if detail:
            return f"{name}: {detail}"
    return name


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
