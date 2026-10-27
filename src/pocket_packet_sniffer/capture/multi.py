"""Concurrent fan-in for independent passive capture backends."""

from __future__ import annotations

from collections.abc import Iterable
from threading import Event, Lock, Thread

from .base import Capturer, PacketCallback
from .errors import CaptureError, CaptureStartupError


class MultiCapturer(Capturer):
    """Run two or more Capturer instances concurrently behind one interface.

    A shared stop event and callback preserve the existing application boundary.
    Count is a maximum for the combined stream, not a per-backend count.
    One backend failure requests shutdown of every peer before returning.
    """

    name = "multi"

    def __init__(self, capturers: Iterable[Capturer]) -> None:
        self.capturers = tuple(capturers)
        if len(self.capturers) < 2:
            raise ValueError("MultiCapturer requires at least two backends")
        if any(not isinstance(capturer, Capturer) for capturer in self.capturers):
            raise TypeError("every backend must implement Capturer")
        if len({id(capturer) for capturer in self.capturers}) != len(self.capturers):
            raise ValueError("each backend must be a distinct Capturer instance")

    def capture(
        self,
        on_packet: PacketCallback,
        stop_event: Event,
        count: int | None = None,
    ) -> None:
        """Fan packets from every backend into one callback until stopped."""
        if count is not None and (
            not isinstance(count, int) or isinstance(count, bool) or count < 1
        ):
            raise ValueError("count must be a positive integer or None")

        state_lock = Lock()
        delivered = 0
        errors: list[Exception] = []

        def dispatch(packet) -> None:
            nonlocal delivered
            with state_lock:
                if stop_event.is_set() or (count is not None and delivered >= count):
                    return
                delivered += 1
                should_stop = count is not None and delivered >= count
            on_packet(packet)
            if should_stop:
                stop_event.set()

        def run_backend(capturer: Capturer) -> None:
            try:
                capturer.capture(dispatch, stop_event)
            except Exception as exc:
                with state_lock:
                    errors.append(exc)
                stop_event.set()

        workers = [
            Thread(
                target=run_backend,
                args=(capturer,),
                name=f"pps-capture-{getattr(capturer, 'name', type(capturer).__name__)}",
                daemon=True,
            )
            for capturer in self.capturers
        ]
        for worker in workers:
            worker.start()

        try:
            while any(worker.is_alive() for worker in workers):
                if stop_event.wait(0.05):
                    break
        except KeyboardInterrupt:
            stop_event.set()
            raise
        finally:
            if errors:
                stop_event.set()
            for worker in workers:
                worker.join()

        if errors:
            error = errors[0]
            if isinstance(error, CaptureError):
                raise error
            raise CaptureStartupError("a concurrent capture backend failed") from error
