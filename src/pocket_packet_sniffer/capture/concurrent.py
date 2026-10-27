"""Concurrent orchestration for interchangeable passive capture backends.

This coordinator owns thread lifecycle only. Packet analysis, storage and
presentation remain supplied by the caller through the packet callback.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from threading import Event, Lock, Thread

from .base import Capturer
from .models import CapturedPacket


@dataclass(frozen=True, slots=True)
class BackendCaptureResult:
    backend: str
    error: Exception | None


class ConcurrentCaptureError(RuntimeError):
    """One or more backends failed while a concurrent capture was running."""

    def __init__(self, results: Sequence[BackendCaptureResult]) -> None:
        self.results = tuple(results)
        failed = [result.backend for result in results if result.error is not None]
        super().__init__("capture backend failure(s): " + ", ".join(failed))


class ConcurrentCaptureRunner:
    """Run two or more Capturer instances concurrently with a shared stop event."""

    def __init__(self, capturers: Sequence[Capturer]) -> None:
        self.capturers = tuple(capturers)
        if len(self.capturers) < 2:
            raise ValueError("concurrent capture requires at least two capturers")
        names = [str(getattr(item, "name", type(item).__name__)) for item in self.capturers]
        if len(set(names)) != len(names):
            raise ValueError("each concurrent capturer must have a unique name")
        self._stop_event = Event()
        self._lock = Lock()
        self._results: list[BackendCaptureResult] = []

    def stop(self) -> None:
        """Ask all backends to stop as soon as their implementation permits."""
        self._stop_event.set()

    @property
    def stop_event(self) -> Event:
        """Expose the shared stop signal for controlled shutdown and tests."""
        return self._stop_event

    def run(
        self,
        on_packet: Callable[[str, CapturedPacket], None],
        *,
        count_per_backend: int | None = None,
    ) -> tuple[BackendCaptureResult, ...]:
        """Run all backends and return per-backend results after joining threads.

        The callback receives the backend name alongside the captured record,
        preserving context without coupling the coordinator to Analysis or
        Storage. Callback failures stop all workers and are returned as errors.
        """
        if not callable(on_packet):
            raise TypeError("on_packet must be callable")
        if count_per_backend is not None and (
            not isinstance(count_per_backend, int)
            or isinstance(count_per_backend, bool)
            or count_per_backend < 1
        ):
            raise ValueError("count_per_backend must be a positive integer or None")
        self._stop_event.clear()
        with self._lock:
            self._results = []

        def worker(capturer: Capturer) -> None:
            name = str(getattr(capturer, "name", type(capturer).__name__))
            error: Exception | None = None

            def deliver(packet: CapturedPacket) -> None:
                try:
                    on_packet(name, packet)
                except Exception:
                    self._stop_event.set()
                    raise

            try:
                capturer.capture(deliver, self._stop_event, count=count_per_backend)
            except Exception as exc:
                error = exc
                self._stop_event.set()
            finally:
                with self._lock:
                    self._results.append(BackendCaptureResult(name, error))

        threads = [Thread(target=worker, args=(capturer,), name=f"capture-{getattr(capturer, 'name', index)}")
                   for index, capturer in enumerate(self.capturers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        results = tuple(sorted(self._results, key=lambda result: result.backend))
        if any(result.error is not None for result in results):
            raise ConcurrentCaptureError(results)
        return results
