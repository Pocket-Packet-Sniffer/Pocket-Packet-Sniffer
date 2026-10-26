"""Storage-layer packet and summary contracts.

PacketRecord is the common, analysis-to-storage value object. Addresses are
strings so that IPv4, IPv6, MAC, and analyzer-specific identifiers are valid.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .errors import InvalidRecordError


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """One analyzed packet plus its original captured bytes.

    ``timestamp`` must be timezone-aware. ``link_type`` uses the PCAP
    LINKTYPE/DLT number and must be consistent within a capture session.
    ``original_length`` defaults to the captured byte length.
    """

    session_id: str
    protocol: str
    source_address: str | None
    destination_address: str | None
    timestamp: datetime
    packet_data: bytes
    link_type: int = 1  # Ethernet, the PCAP/pcap-linktypes default.
    original_length: int | None = None
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise InvalidRecordError("session_id must be a non-empty string")
        if not isinstance(self.record_id, str) or not self.record_id.strip():
            raise InvalidRecordError("record_id must be a non-empty string")
        if not isinstance(self.protocol, str) or not self.protocol.strip():
            raise InvalidRecordError("protocol must be a non-empty string")
        for name in ("source_address", "destination_address"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise InvalidRecordError(f"{name} must be a non-empty string or None")
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise InvalidRecordError("timestamp must be a timezone-aware datetime")
        try:
            if self.timestamp.utcoffset() is None:
                raise InvalidRecordError("timestamp must be a timezone-aware datetime")
            utc_timestamp = self.timestamp.astimezone(timezone.utc)
            epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
            delta = utc_timestamp - epoch
            timestamp_us = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
        except (OverflowError, OSError, ValueError, TypeError) as exc:
            raise InvalidRecordError("timestamp is outside the supported PCAP range") from exc
        if not 0 <= timestamp_us <= 0xFFFFFFFF * 1_000_000 + 999_999:
            raise InvalidRecordError("timestamp must fit the classic PCAP seconds field")
        for name, value in (("session_id", self.session_id), ("record_id", self.record_id), ("protocol", self.protocol)):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise InvalidRecordError(f"{name} must be valid UTF-8 text") from exc
        for name, value in (("source_address", self.source_address), ("destination_address", self.destination_address)):
            if value is not None:
                try:
                    value.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise InvalidRecordError(f"{name} must be valid UTF-8 text") from exc
        if not isinstance(self.packet_data, bytes):
            raise InvalidRecordError("packet_data must be bytes")
        if not self.packet_data:
            raise InvalidRecordError("packet_data must not be empty")
        if not isinstance(self.link_type, int) or isinstance(self.link_type, bool):
            raise InvalidRecordError("link_type must be an integer")
        if not 0 <= self.link_type <= 0xFFFFFFFF:
            raise InvalidRecordError("link_type is outside the PCAP range")
        original = len(self.packet_data) if self.original_length is None else self.original_length
        if not isinstance(original, int) or isinstance(original, bool) or original < len(self.packet_data):
            raise InvalidRecordError("original_length must be an integer at least packet_data length")
        if original > 0xFFFFFFFF:
            raise InvalidRecordError("original_length is outside the classic PCAP range")
        if len(self.packet_data) > 65535:
            raise InvalidRecordError("packet_data exceeds the configured PCAP snap length (65535 bytes)")
        object.__setattr__(self, "protocol", self.protocol.strip().upper())
        object.__setattr__(self, "timestamp", utc_timestamp)
        object.__setattr__(self, "original_length", original)


@dataclass(frozen=True, slots=True)
class SessionSummary:
    """Count and time bounds for one stored capture session."""

    session_id: str
    packet_count: int
    first_packet_at: datetime | None
    last_packet_at: datetime | None
