"""Dependency-free replay of classic PCAP files for tests and demonstrations."""

from __future__ import annotations

import math
import os
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from typing import BinaryIO

from .base import Capturer, PacketCallback
from .errors import CaptureCallbackError, CaptureFileError
from .models import CapturedPacket

_GLOBAL_REMAINDER = struct.Struct("HHIIII")
_PACKET_HEADER = struct.Struct("IIII")
_MAX_SNAPLEN = 16 * 1024 * 1024
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),  # little-endian microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),  # big-endian microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little-endian nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big-endian nanoseconds
}


class PcapFileCapturer(Capturer):
    """Replay supported classic PCAP files without needing live capture rights.

    The source label is the filename. PCAPNG is not supported by this small
    classic-PCAP reader and will produce an actionable ``CaptureFileError``.
    """

    name = "pcap-file"

    def __init__(self, path: str | os.PathLike[str], delay: float = 0.0):
        self.path = Path(path).expanduser()
        if isinstance(delay, bool) or not isinstance(delay, (int, float)):
            raise ValueError("delay must be a non-negative number of seconds")
        if not math.isfinite(delay) or delay < 0:
            raise ValueError("delay must be a finite, non-negative number of seconds")
        self.delay = float(delay)

    def capture(
        self,
        on_packet: PacketCallback,
        stop_event: Event,
        count: int | None = None,
    ) -> None:
        _validate_capture_args(on_packet, stop_event, count)
        if not self.path.is_file():
            raise CaptureFileError(f"PCAP file '{self.path}' does not exist or is not a regular file.")

        delivered = 0
        try:
            with self.path.open("rb") as stream:
                endian, fraction_base, snaplen, link_type = self._read_global_header(stream)
                while not stop_event.is_set():
                    if count is not None and delivered >= count:
                        break
                    packet = self._read_packet(stream, endian, fraction_base, snaplen, link_type)
                    if packet is None:
                        break
                    try:
                        on_packet(packet)
                    except Exception as exc:
                        # Preserve actionable callback detail without including packet bytes.
                        detail = f"{type(exc).__name__}: {exc}"
                        raise CaptureCallbackError(
                            "Analysis callback failed while processing a replayed packet "
                            f"({detail})."
                        ) from exc
                    delivered += 1
                    if self.delay and stop_event.wait(self.delay):
                        break
        except CaptureFileError:
            raise
        except CaptureCallbackError:
            raise
        except PermissionError as exc:
            raise CaptureFileError(
                f"Permission denied reading PCAP file '{self.path}'. Check the file permissions."
            ) from exc
        except OSError as exc:
            raise CaptureFileError(f"Could not read PCAP file '{self.path}': {exc}") from exc
        except (OverflowError, ValueError, struct.error) as exc:
            raise CaptureFileError(f"PCAP file '{self.path}' contains invalid packet data: {exc}") from exc

    def _read_global_header(self, stream: BinaryIO) -> tuple[str, int, int, int]:
        magic = stream.read(4)
        if len(magic) != 4 or magic not in _MAGIC:
            raise CaptureFileError(
                f"'{self.path}' is not a supported classic PCAP file (PCAPNG is not supported by this backend)."
            )
        endian, fraction_base = _MAGIC[magic]
        remainder = stream.read(_GLOBAL_REMAINDER.size)
        if len(remainder) != _GLOBAL_REMAINDER.size:
            raise CaptureFileError(f"PCAP file '{self.path}' has a truncated global header.")
        major, minor, _timezone, _sigfigs, snaplen, link_type = struct.unpack(f"{endian}HHIIII", remainder)
        if (major, minor) != (2, 4):
            raise CaptureFileError(f"PCAP file '{self.path}' uses unsupported version {major}.{minor}; expected 2.4.")
        if snaplen <= 0 or snaplen > _MAX_SNAPLEN:
            raise CaptureFileError(f"PCAP file '{self.path}' has an invalid snap length ({snaplen}).")
        return endian, fraction_base, snaplen, link_type

    def _read_packet(
        self,
        stream: BinaryIO,
        endian: str,
        fraction_base: int,
        snaplen: int,
        link_type: int,
    ) -> CapturedPacket | None:
        packet_header = stream.read(_PACKET_HEADER.size)
        if not packet_header:
            return None
        if len(packet_header) != _PACKET_HEADER.size:
            raise CaptureFileError(f"PCAP file '{self.path}' ends with a truncated packet header.")
        seconds, fraction, captured_length, original_length = struct.unpack(f"{endian}IIII", packet_header)
        if fraction >= fraction_base:
            raise CaptureFileError(f"PCAP file '{self.path}' contains an invalid timestamp fraction.")
        if captured_length <= 0 or captured_length > snaplen or captured_length > _MAX_SNAPLEN:
            raise CaptureFileError(f"PCAP file '{self.path}' contains an invalid captured packet length.")
        if original_length < captured_length:
            raise CaptureFileError(f"PCAP file '{self.path}' contains an invalid original packet length.")
        packet_data = stream.read(captured_length)
        if len(packet_data) != captured_length:
            raise CaptureFileError(f"PCAP file '{self.path}' ends with a truncated packet payload.")
        microseconds = fraction if fraction_base == 1_000_000 else fraction // 1_000
        timestamp = datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(microseconds=microseconds)
        return CapturedPacket(
            timestamp=timestamp,
            packet_data=packet_data,
            interface=self.path.name,
            link_type=link_type,
            original_length=original_length,
            capture_backend=self.name,
        )


def _validate_capture_args(on_packet: PacketCallback, stop_event: Event, count: int | None) -> None:
    if not callable(on_packet):
        raise TypeError("on_packet must be callable")
    if not hasattr(stop_event, "is_set") or not hasattr(stop_event, "wait"):
        raise TypeError("stop_event must provide is_set() and wait() methods")
    if count is not None and (not isinstance(count, int) or isinstance(count, bool) or count < 1):
        raise ValueError("count must be a positive integer or None")
