"""Local filesystem control channel for explicit cross-terminal capture stop requests."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from threading import Event, Thread
from time import time


class CaptureControlError(RuntimeError):
    """Raised when capture control state cannot be registered safely."""


class CaptureControl:
    """Coordinate an active capture and a separate CLI stop request locally.

    Control markers contain only session metadata. They live in the configured
    private storage directory and do not contain packet bytes or network data.
    """

    def __init__(
        self,
        storage_dir: str | os.PathLike[str],
        session_id: str,
        backend: str,
        *,
        poll_interval: float = 0.1,
    ) -> None:
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        if not isinstance(backend, str) or not backend.strip():
            raise ValueError("backend must be a non-empty string")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        self.directory = Path(storage_dir).expanduser().resolve()
        self.session_id = session_id
        self.backend = backend
        self.poll_interval = poll_interval
        token = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        self.active_path = self.directory / f".pps-active-{token}.json"
        self.stop_path = self.directory / f".pps-stop-{token}.request"
        self._watcher_stop = Event()
        self._stop_event: Event | None = None
        self._thread: Thread | None = None
        self._activated = False

    @staticmethod
    def _process_is_alive(pid: object) -> bool:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            # Some Windows process-access errors do not distinguish a denied
            # query from an absent process. Preserve the marker conservatively.
            return True
        return True

    @staticmethod
    def _private_file(path: Path, content: str) -> None:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            path.chmod(0o600)

    def activate(self) -> None:
        """Register the active session, refusing a second owner for that ID."""
        if not self.directory.is_dir():
            raise CaptureControlError("capture storage directory does not exist")
        if self.active_path.exists():
            try:
                state = json.loads(self.active_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise CaptureControlError(
                    "capture control marker is unreadable; inspect/remove the stale marker before retrying"
                ) from None
            if self._process_is_alive(state.get("pid")):
                raise CaptureControlError(
                    f"capture session {self.session_id!r} already has an active process"
                )
            self.active_path.unlink(missing_ok=True)
            self.stop_path.unlink(missing_ok=True)
        else:
            # A stop request without a matching live marker is stale.
            self.stop_path.unlink(missing_ok=True)

        state = {
            "session_id": self.session_id,
            "backend": self.backend,
            "pid": os.getpid(),
            "started_unix": time(),
        }
        try:
            self._private_file(self.active_path, json.dumps(state, separators=(",", ":")))
        except FileExistsError as exc:
            raise CaptureControlError(
                f"capture session {self.session_id!r} was registered concurrently"
            ) from exc
        except OSError as exc:
            raise CaptureControlError("unable to register capture control state") from exc
        self._activated = True

    def start_watcher(self, stop_event: Event) -> None:
        """Start polling for a stop request from another CLI process."""
        if not self._activated:
            raise CaptureControlError("activate capture control before starting the watcher")
        if self._thread is not None:
            raise CaptureControlError("capture stop watcher is already running")
        self._stop_event = stop_event
        self._thread = Thread(
            target=self._watch_for_stop,
            name="pps-stop-request-watcher",
            daemon=True,
        )
        self._thread.start()

    def _watch_for_stop(self) -> None:
        while not self._watcher_stop.wait(self.poll_interval):
            if self._stop_event is None or self._stop_event.is_set():
                return
            if self.stop_path.exists():
                self._stop_event.set()
                self.stop_path.unlink(missing_ok=True)
                return

    def close(self) -> None:
        """Stop the watcher and remove local control markers on session exit."""
        self._watcher_stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.poll_interval * 4))
        self.stop_path.unlink(missing_ok=True)
        self.active_path.unlink(missing_ok=True)
        self._activated = False

    @classmethod
    def request_stop(
        cls,
        storage_dir: str | os.PathLike[str],
        session_id: str,
    ) -> bool:
        """Request a stop for a registered session; return False if not active."""
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        directory = Path(storage_dir).expanduser().resolve()
        token = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        active_path = directory / f".pps-active-{token}.json"
        stop_path = directory / f".pps-stop-{token}.request"
        if not active_path.is_file():
            return False
        try:
            state = json.loads(active_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise CaptureControlError("active capture control marker is unreadable") from None
        if state.get("session_id") != session_id:
            raise CaptureControlError("active capture marker does not match the requested session")
        if not cls._process_is_alive(state.get("pid")):
            active_path.unlink(missing_ok=True)
            stop_path.unlink(missing_ok=True)
            return False
        if stop_path.exists():
            return True
        try:
            cls._private_file(
                stop_path,
                json.dumps({"session_id": session_id, "requested_unix": time()}, separators=(",", ":")),
            )
        except FileExistsError:
            return True
        except OSError as exc:
            raise CaptureControlError("unable to write local stop request") from exc
        return True
