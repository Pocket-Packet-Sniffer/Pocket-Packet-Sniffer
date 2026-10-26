"""Common interface for passive capture backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from threading import Event

from .models import CapturedPacket

PacketCallback = Callable[[CapturedPacket], None]


class Capturer(ABC):
    """Strategy interface shared by live and file-based capture backends.

    Implementations call ``on_packet`` with a backend-neutral ``CapturedPacket``.
    ``capture`` blocks until the stop event is set, the requested count is met,
    or the source is exhausted. Backends must be passive and must not transmit
    captured or synthetic traffic.
    """

    name = "capturer"

    @abstractmethod
    def capture(
        self,
        on_packet: PacketCallback,
        stop_event: Event,
        count: int | None = None,
    ) -> None:
        """Deliver raw packets to ``on_packet`` or raise a typed ``CaptureError``."""
