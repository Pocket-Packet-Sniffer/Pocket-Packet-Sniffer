"""Backend-neutral records emitted by the Capture Layer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class CapturedPacket:
    """One raw captured packet with its capture metadata.

    `packet_data` is the original link-layer frame as captured. The record is
    deliberately independent of Scapy so Analysis can consume packets from any
    backend without backend-specific branching.
    """

    timestamp: datetime
    packet_data: bytes
    interface: str
    link_type: int
    original_length: int

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be a timezone-aware datetime")
        if self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be a timezone-aware datetime")
        if not isinstance(self.packet_data, bytes):
            raise TypeError("packet_data must be bytes")
        if not self.packet_data:
            raise ValueError("packet_data must not be empty")
        if not isinstance(self.interface, str) or not self.interface.strip():
            raise ValueError("interface must be a non-empty string")
        if not isinstance(self.link_type, int) or isinstance(self.link_type, bool):
            raise ValueError("link_type must be an integer")
        if not 0 <= self.link_type <= 0xFFFFFFFF:
            raise ValueError("link_type must fit the classic PCAP field")
        if (
            not isinstance(self.original_length, int)
            or isinstance(self.original_length, bool)
            or self.original_length < len(self.packet_data)
            or self.original_length > 0xFFFFFFFF
        ):
            raise ValueError("original_length must be at least packet_data length and fit PCAP")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(timezone.utc))
