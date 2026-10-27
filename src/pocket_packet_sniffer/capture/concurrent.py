"""Concurrent fan-in for independent passive capture backends."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from threading import Event, Lock, Thread
from .base import Capturer, PacketCallback
from .errors import CaptureStartupError
from .models import CapturedPacket
from .pcap_file import _validate_capture_args


class ConcurrentCapturer(Capturer):
    """Run two or more capture strategies and fan packets into one callback.

    Each packet retains its source interface and a backend identifier. All
    backends share cancellation and an optional aggregate packet count. An
    exhausted file replay does not stop a still-running live backend.
    """

    name = "concurrent"

    def __init__(self, capturers: Iterable[Capturer]) -> None:
        self.capturers = tuple(capturers)
        if len(self.capturers) < 2:
            raise ValueError("concurrent capture requires at least two capturers")
        if any(not isinstance(capturer, Capturer) for capturer in self.capturers):
            raise TypeError("all concurrent backends must implement Capturer")
        if len({id(capturer) for capturer in self.capturers}) != len(self.capturers):
            raise ValueError("a capturer instance cannot be registered more than once")

    def capture(
        self,
        on_packet: PacketCallback,
        stop_event: Event,
        count: int | None = None,
    ) -> None:
        _validate_capture_args(on_packet, stop_event, count)
        if stop_event.is_set():
            return

        backend_stop = Event()
        finished = Event()
        callback_lock = Lock()
        state_lock = Lock()
        delivered = 0
        remaining = len(self.capturers)
        errors: list[Exception] = []

        def dispatch(capturer: Capturer, packet: CapturedPacket) -> None:
            nonlocal delivered
            with callback_lock:
                if stop_event.is_set() or backend_stop.is_set():
                    return
                if count is not None and delivered >= count:
                    backend_stop.set()
                    return
                backend_name = getattr(capturer, "name", type(capturer).__name__)
                tagged_packet = (
                    packet
                    if packet.capture_backend
                    else replace(packet, capture_backend=str(backend_name))
                )
                on_packet(tagged_packet)
                delivered += 1
                if count is not None and delivered >= count:
                    backend_stop.set()

        def run_backend(capturer: Capturer) -> None:
            nonlocal remaining
            try:
                capturer.capture(
                    lambda packet: dispatch(capturer, packet),
                    backend_stop,
                    count=None,
                )
            except Exception as exc:
                with state_lock:
                    errors.append(exc)
                backend_stop.set()
            finally:
                with state_lock:
                    remaining -= 1
                    if remaining == 0:
                        finished.set()

        threads = [
            Thread(
                target=run_backend,
                args=(capturer,),
                name=f"pps-{getattr(capturer, 'name', 'capture')}",
                daemon=True,
            )
            for capturer in self.capturers
        ]
        for thread in threads:
            thread.start()

        while not stop_event.is_set() and not backend_stop.is_set() and not finished.wait(0.02):
            pass
        backend_stop.set()
        for thread in threads:
            thread.join(timeout=5.0)

        stuck = [thread.name for thread in threads if thread.is_alive()]
        if stuck:
            raise CaptureStartupError(
                "Capture backend did not stop after cancellation: " + ", ".join(stuck)
            )
        if errors:
            raise errors[0]
