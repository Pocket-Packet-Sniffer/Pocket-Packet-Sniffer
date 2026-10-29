"""Passive live packet capture using Scapy's asynchronous sniffer."""

from __future__ import annotations

import math
import time
from datetime import datetime, timezone
from threading import Event, Lock
from typing import Any

from .base import Capturer, PacketCallback
from .errors import (
    CaptureBackendUnavailableError,
    CaptureCallbackError,
    CaptureError,
    CaptureInterfaceError,
    CapturePermissionError,
    CaptureStartupError,
    _callback_failure_detail,
)
from .models import CapturedPacket
from .pcap_file import _validate_capture_args


class ScapyCapturer(Capturer):
    """Listen passively on one selected interface via Scapy.

    Scapy is loaded lazily so file replay and unit tests work without it. The
    current process may need elevated capture privileges and a supported driver.
    No send/inject/replay APIs are used by this backend.
    """

    name = "scapy-live"

    def __init__(
        self,
        interface: str,
        bpf_filter: str | None = None,
        *,
        startup_timeout: float = 3.0,
        poll_interval: float = 0.05,
    ):
        if not isinstance(interface, str) or not interface.strip():
            raise ValueError("interface must be a non-empty name")
        if bpf_filter is not None and not isinstance(bpf_filter, str):
            raise ValueError("bpf_filter must be a string or None")
        if (
            not math.isfinite(startup_timeout)
            or not math.isfinite(poll_interval)
            or startup_timeout <= 0
            or poll_interval <= 0
        ):
            raise ValueError("startup_timeout and poll_interval must be finite, positive numbers")
        self.interface = interface.strip()
        self.bpf_filter = bpf_filter
        self.startup_timeout = float(startup_timeout)
        self.poll_interval = float(poll_interval)

    def capture(
        self,
        on_packet: PacketCallback,
        stop_event: Event,
        count: int | None = None,
    ) -> None:
        _validate_capture_args(on_packet, stop_event, count)
        try:
            from scapy.all import AsyncSniffer, conf, get_if_list
        except ImportError as exc:
            raise CaptureBackendUnavailableError(
                "Live capture requires Scapy. Install the project's capture dependencies before using this backend."
            ) from exc

        try:
            interfaces = list(get_if_list())
        except Exception as exc:
            raise CaptureStartupError(f"Could not enumerate network interfaces: {exc}") from exc

        # On Windows, get_if_list() commonly returns Npcap device paths while
        # conf.ifaces also exposes friendly names such as "Wi-Fi". Accept
        # either form and pass the resolved Scapy interface object to the sniffer.
        resolved_interface: Any = self.interface
        available_names = {str(name) for name in interfaces}
        scapy_interfaces = getattr(conf, "ifaces", None)
        try:
            interface_objects = list(scapy_interfaces.values()) if scapy_interfaces is not None else []
        except (AttributeError, TypeError):
            interface_objects = []

        if self.interface not in available_names:
            matched_interface = next(
                (
                    candidate
                    for candidate in interface_objects
                    if self.interface
                    in {
                        str(getattr(candidate, attribute, ""))
                        for attribute in ("name", "description", "network_name")
                        if getattr(candidate, attribute, None) is not None
                    }
                ),
                None,
            )
            if matched_interface is None:
                for candidate in interface_objects:
                    for attribute in ("name", "description", "network_name"):
                        value = getattr(candidate, attribute, None)
                        if value is not None:
                            available_names.add(str(value))
                available = ", ".join(sorted(available_names)) or "none detected"
                raise CaptureInterfaceError(
                    f"Interface '{self.interface}' is unavailable. Available interfaces: {available}. "
                    "Check the interface name, adapter state, and driver installation."
                )
            resolved_interface = matched_interface

        if stop_event.is_set():
            return

        started = Event()
        callback_error: list[Exception] = []
        count_lock = Lock()
        delivered = 0

        def handle(packet: Any) -> None:
            nonlocal delivered
            if stop_event.is_set():
                return
            try:
                raw = bytes(packet)
                if not raw:
                    return
                packet_time = getattr(packet, "time", None)
                if packet_time is None:
                    timestamp = datetime.now(timezone.utc)
                else:
                    timestamp = datetime.fromtimestamp(float(packet_time), tz=timezone.utc)
                sniffed_on = getattr(packet, "sniffed_on", None) or self.interface
                layer_map = getattr(getattr(conf, "l2types", None), "layer2num", {})
                link_type = layer_map.get(type(packet))
                if link_type is None:
                    packet_type = type(packet).__name__
                    if packet_type == "BTLE_RF":
                        link_type = 256
                    elif packet_type.startswith("BTLE"):
                        link_type = 251
                    elif packet_type.startswith("Dot11"):
                        link_type = 105
                    else:
                        link_type = 1
                record = CapturedPacket(
                    timestamp=timestamp,
                    packet_data=raw,
                    interface=str(sniffed_on),
                    link_type=int(link_type),
                    original_length=max(len(raw), int(getattr(packet, "wirelen", len(raw)) or len(raw))),
                    capture_backend=self.name,
                )
                on_packet(record)
                with count_lock:
                    delivered += 1
            except Exception as exc:
                callback_error.append(exc)

        sniffer = None
        try:
            sniffer = AsyncSniffer(
                iface=resolved_interface,
                store=False,
                prn=handle,
                filter=self.bpf_filter,
                started_callback=started.set,
            )
            sniffer.start()
            deadline = time.monotonic() + self.startup_timeout
            while not started.is_set() and time.monotonic() < deadline:
                thread = getattr(sniffer, "thread", None)
                if thread is not None and not thread.is_alive():
                    break
                time.sleep(min(self.poll_interval, max(deadline - time.monotonic(), 0)))

            if not started.is_set():
                # Join briefly to let Scapy publish a startup exception, if any.
                thread = getattr(sniffer, "thread", None)
                if thread is not None:
                    thread.join(timeout=0.1)
                startup_error = getattr(sniffer, "exception", None)
                if startup_error is not None:
                    raise _translate_backend_error(startup_error, self.interface)
                raise CaptureStartupError(
                    f"Capture on '{self.interface}' did not start within {self.startup_timeout:g} seconds. "
                    "Check adapter state, capture driver, and permissions."
                )

            while True:
                if stop_event.is_set() or callback_error:
                    break
                with count_lock:
                    count_reached = count is not None and delivered >= count
                if count_reached or not getattr(sniffer, "running", True):
                    break
                stop_event.wait(self.poll_interval)

            if getattr(sniffer, "running", False):
                sniffer.stop(join=True)
            else:
                sniffer.join()

            if callback_error:
                cause = callback_error[0]
                if isinstance(cause, CaptureCallbackError):
                    raise cause
                detail = _callback_failure_detail(cause)
                raise CaptureCallbackError(
                    f"Analysis callback failed while processing a live packet ({detail})."
                ) from cause
            backend_error = getattr(sniffer, "exception", None)
            if backend_error is not None:
                raise _translate_backend_error(backend_error, self.interface)
        except KeyboardInterrupt:
            # Ctrl+C must stop the background sniffer before the CLI returns.
            stop_event.set()
            _stop_sniffer_safely(sniffer)
            raise
        except CaptureError:
            _stop_sniffer_safely(sniffer)
            raise
        except Exception as exc:
            _stop_sniffer_safely(sniffer)
            raise _translate_backend_error(exc, self.interface) from exc


def _stop_sniffer_safely(sniffer: Any) -> None:
    if sniffer is None:
        return
    try:
        if getattr(sniffer, "running", False):
            sniffer.stop(join=True)
        else:
            thread = getattr(sniffer, "thread", None)
            if thread is not None and thread.is_alive():
                thread.join(timeout=0.2)
    except Exception:
        # Preserve the primary startup/capture error; cleanup is best-effort.
        pass


def _translate_backend_error(exc: Exception, interface: str) -> CaptureError:
    message = str(exc) or exc.__class__.__name__
    lowered = message.lower()
    if isinstance(exc, PermissionError) or any(
        marker in lowered
        for marker in ("permission denied", "operation not permitted", "access is denied", "not permitted")
    ):
        return CapturePermissionError(
            f"Permission denied while capturing on '{interface}'. On Linux/macOS use the approved capture privileges; "
            "on Windows, verify Npcap and run with the required permissions."
        )
    if isinstance(exc, OSError):
        return CaptureStartupError(
            f"Could not capture on '{interface}': {message}. Check that the interface is up and its capture driver works."
        )
    return CaptureStartupError(f"Live capture on '{interface}' failed to start or continue: {message}.")
