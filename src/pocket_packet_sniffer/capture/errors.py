"""Stable, actionable errors raised by Capture Layer backends."""

from __future__ import annotations

import traceback


def _callback_failure_detail(exc: Exception) -> str:
    """Return safe diagnostic context for an exception raised by a packet callback.

    Project-owned exceptions and SQLite errors use sanitized domain messages.
    Arbitrary callback exception text is intentionally omitted so custom code
    cannot accidentally print captured data to the terminal. Follow a short
    cause chain to show the underlying storage error when available.
    """
    def safe_detail(error: Exception) -> str:
        error_type = type(error)
        name = error_type.__name__
        module = error_type.__module__
        if module.startswith("pocket_packet_sniffer.") or module == "sqlite3":
            detail = " ".join(str(error).split())[:180]
            if detail:
                return f"{name}: {detail}"
        # For other exception types, never print arbitrary exception text. Show
        # the final source locations instead, so programming errors stay debuggable.
        frames = traceback.extract_tb(error.__traceback__)
        if frames:
            locations = []
            for frame in frames[-2:]:
                filename = frame.filename.replace("\\\\", "/").rsplit("/", 1)[-1]
                locations.append(f"{filename}:{frame.lineno} in {frame.name}")
            return f"{name} at " + " <- ".join(locations)
        return name

    details: list[str] = []
    current: BaseException | None = exc
    seen: set[int] = set()
    for _ in range(3):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        if isinstance(current, Exception):
            detail = safe_detail(current)
        else:
            detail = type(current).__name__
        if not details or detail != details[-1]:
            details.append(detail)
        # Only traverse explicit causes/contexts from project and standard
        # storage errors. Avoid leaking messages from arbitrary custom errors.
        current_module = type(current).__module__
        if not (
            current_module.startswith("pocket_packet_sniffer.")
            or current_module == "sqlite3"
        ):
            break
        current = current.__cause__ or current.__context__
    return " <- caused by ".join(details)


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
