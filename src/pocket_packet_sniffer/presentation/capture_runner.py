"""Application-facing wrapper for capture failures and graceful interruption.

The full CLI/session command will choose a backend and supply its Analysis
callback. This helper centralizes the exit-code and user-facing error contract
so callers do not need to expose backend exceptions as tracebacks.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from threading import Event
from typing import TextIO

from pocket_packet_sniffer.capture import CaptureError, CapturedPacket, Capturer

EXIT_SUCCESS = 0
EXIT_CAPTURE_ERROR = 2
EXIT_INTERRUPTED = 130

PacketConsumer = Callable[[CapturedPacket], None]


def run_capture_with_error_handling(
    capturer: Capturer,
    on_packet: PacketConsumer,
    stop_event: Event,
    *,
    count: int | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run a backend and return a stable CLI-style exit status.

    Capture/domain errors are printed as one actionable line and return
    EXIT_CAPTURE_ERROR rather than leaking a traceback. Ctrl+C requests
    cooperative stop and returns the conventional interrupted status.
    Unexpected programming errors are not swallowed.
    """
    error_stream = stderr if stderr is not None else sys.stderr
    try:
        capturer.capture(on_packet, stop_event, count=count)
    except CaptureError as exc:
        print(f"capture error: {exc}", file=error_stream)
        return EXIT_CAPTURE_ERROR
    except KeyboardInterrupt:
        stop_event.set()
        print("capture interrupted", file=error_stream)
        return EXIT_INTERRUPTED
    return EXIT_SUCCESS
