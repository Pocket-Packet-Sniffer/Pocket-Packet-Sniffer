"""PCAP packet files with an indexed SQLite metadata repository."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import struct
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from .errors import (
    DuplicateRecordError,
    InvalidRecordError,
    RepositoryError,
    StorageAccessError,
    StorageCorruptionError,
    StorageUnavailableError,
)
from .models import PacketRecord, SessionSummary
from .repository import Repository

_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_VERSION = (2, 4)
_PCAP_SNAPLEN = 65535
_GLOBAL_HEADER = struct.Struct("<IHHIIII")
_PACKET_HEADER = struct.Struct("<IIII")
_PCAP_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _timestamp_us(value: datetime) -> int:
    delta = value.astimezone(timezone.utc) - _PCAP_EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _from_timestamp_us(value: int) -> datetime:
    return _PCAP_EPOCH + timedelta(microseconds=value)


class PcapSqliteRepository(Repository):
    """Store session packets in classic PCAP and searchable fields in SQLite.

    Each session receives its own PCAP because classic PCAP stores one link
    type in its global header. The SQLite database indexes records and stores
    only packet metadata plus safe PCAP offsets, not packet contents.
    """

    def __init__(self, directory: str | os.PathLike[str], *, timeout: float = 5.0):
        self.directory = Path(directory).expanduser()
        self.database_path = self.directory / "metadata.sqlite3"
        self.timeout = timeout
        self._lock = threading.RLock()
        if timeout <= 0:
            raise InvalidRecordError("timeout must be positive")
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name == "posix":
                # mkdir(mode=...) does not tighten permissions on an existing directory.
                self.directory.chmod(0o700)
            self._initialize()
            self._restrict_permissions(self.database_path)
        except PermissionError as exc:
            raise StorageAccessError(f"cannot access storage directory: {self.directory}") from exc
        except OSError as exc:
            raise StorageUnavailableError(f"cannot initialize storage directory: {self.directory}") from exc
        except sqlite3.Error as exc:
            raise StorageUnavailableError("cannot initialize metadata database") from exc

    def _connect(self, *, initialize: bool = False) -> sqlite3.Connection:
        if initialize:
            connection = sqlite3.connect(self.database_path, timeout=self.timeout)
        else:
            if not self.database_path.exists():
                raise StorageUnavailableError(f"metadata database is missing: {self.database_path.name}")
            connection = sqlite3.connect(
                f"{self.database_path.as_uri()}?mode=rw", uri=True, timeout=self.timeout
            )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _connection(self, *, initialize: bool = False):
        """Commit or roll back a connection scope and always release its handle."""
        db = self._connect(initialize=initialize)
        try:
            with db:
                yield db
        finally:
            db.close()

    def _initialize(self) -> None:
        if not self.database_path.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(self.database_path, flags, 0o600)
            os.close(fd)
        with self._connection(initialize=True) as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS captures (
                    session_id TEXT PRIMARY KEY,
                    pcap_name TEXT NOT NULL,
                    link_type INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS packets (
                    record_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES captures(session_id),
                    protocol TEXT NOT NULL,
                    source_address TEXT,
                    destination_address TEXT,
                    interface TEXT NOT NULL DEFAULT 'unknown',
                    timestamp_us INTEGER NOT NULL,
                    pcap_offset INTEGER NOT NULL,
                    captured_length INTEGER NOT NULL,
                    original_length INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_packets_protocol_time
                    ON packets(protocol, timestamp_us);
                CREATE INDEX IF NOT EXISTS idx_packets_source_time
                    ON packets(source_address, timestamp_us);
                CREATE INDEX IF NOT EXISTS idx_packets_destination_time
                    ON packets(destination_address, timestamp_us);
                CREATE INDEX IF NOT EXISTS idx_packets_session_time
                    ON packets(session_id, timestamp_us);
                """
            )
            columns = {row["name"] for row in db.execute("PRAGMA table_info(packets)").fetchall()}
            if "interface" not in columns:
                db.execute("ALTER TABLE packets ADD COLUMN interface TEXT NOT NULL DEFAULT 'unknown'")

    @staticmethod
    def _restrict_permissions(path: Path) -> None:
        if os.name == "posix":
            path.chmod(0o600)

    @staticmethod
    def _pcap_name(session_id: str) -> str:
        digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        return f"{digest}.pcap"

    def _pcap_path(self, name: str) -> Path:
        path = (self.directory / name).resolve()
        root = self.directory.resolve()
        if path.parent != root or path.suffix != ".pcap":
            raise StorageCorruptionError("metadata contains an unsafe PCAP path")
        return path

    def _new_pcap(self, path: Path, link_type: int) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(_GLOBAL_HEADER.pack(_PCAP_MAGIC, *_PCAP_VERSION, 0, 0, _PCAP_SNAPLEN, link_type))
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise

    def save(self, record: PacketRecord) -> None:
        if not isinstance(record, PacketRecord):
            raise InvalidRecordError("record must be a PacketRecord")
        pcap_name = self._pcap_name(record.session_id)
        pcap_path = self._pcap_path(pcap_name)
        created_pcap = False
        original_size = 0

        try:
            with self._lock, self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM packets WHERE record_id = ?", (record.record_id,)).fetchone():
                    raise DuplicateRecordError(f"record already exists: {record.record_id}")
                capture = db.execute(
                    "SELECT pcap_name, link_type FROM captures WHERE session_id = ?",
                    (record.session_id,),
                ).fetchone()
                if capture is not None and (capture["pcap_name"] != pcap_name or capture["link_type"] != record.link_type):
                    raise InvalidRecordError("link_type cannot change within a capture session")

                if capture is None:
                    try:
                        self._new_pcap(pcap_path, record.link_type)
                    except FileExistsError as exc:
                        raise StorageCorruptionError("PCAP file exists without matching session metadata") from exc
                    created_pcap = True
                    db.execute(
                        "INSERT INTO captures(session_id, pcap_name, link_type) VALUES (?, ?, ?)",
                        (record.session_id, pcap_name, record.link_type),
                    )

                pcap_path = self._pcap_path(capture["pcap_name"] if capture is not None else pcap_name)
                self._restrict_permissions(pcap_path)
                with pcap_path.open("r+b") as stream:
                    header = stream.read(_GLOBAL_HEADER.size)
                    if len(header) != _GLOBAL_HEADER.size:
                        raise StorageCorruptionError("PCAP global header is truncated")
                    magic, major, minor, _, _, snaplen, link_type = _GLOBAL_HEADER.unpack(header)
                    if (magic, major, minor, snaplen, link_type) != (
                        _PCAP_MAGIC, *_PCAP_VERSION, _PCAP_SNAPLEN, record.link_type
                    ):
                        raise StorageCorruptionError("PCAP header does not match session metadata")
                    stream.seek(0, os.SEEK_END)
                    original_size = stream.tell()
                    offset = original_size
                    seconds, micros = divmod(_timestamp_us(record.timestamp), 1_000_000)
                    if seconds < 0 or micros < 0:
                        raise InvalidRecordError("PCAP timestamps before the Unix epoch are unsupported")
                    stream.write(_PACKET_HEADER.pack(seconds, micros, len(record.packet_data), record.original_length))
                    stream.write(record.packet_data)
                    stream.flush()
                    os.fsync(stream.fileno())

                db.execute(
                    """INSERT INTO packets(record_id, session_id, protocol, source_address,
                       destination_address, interface, timestamp_us, pcap_offset, captured_length, original_length)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record.record_id, record.session_id, record.protocol,
                        record.source_address, record.destination_address, record.interface,
                        _timestamp_us(record.timestamp), offset, len(record.packet_data), record.original_length,
                    ),
                )
                db.commit()
        except DuplicateRecordError:
            raise
        except InvalidRecordError:
            raise
        except StorageCorruptionError:
            if created_pcap:
                try:
                    pcap_path.unlink()
                except OSError:
                    pass
            raise
        except PermissionError as exc:
            self._rollback_pcap(pcap_path, original_size, created_pcap)
            raise StorageAccessError("permission denied while saving packet") from exc
        except FileNotFoundError as exc:
            self._rollback_pcap(pcap_path, original_size, created_pcap)
            raise StorageUnavailableError("capture or metadata file is unavailable") from exc
        except sqlite3.IntegrityError as exc:
            self._rollback_pcap(pcap_path, original_size, created_pcap)
            if "packets.record_id" in str(exc):
                raise DuplicateRecordError(f"record already exists: {record.record_id}") from exc
            raise RepositoryError("metadata constraint rejected packet") from exc
        except sqlite3.Error as exc:
            self._rollback_pcap(pcap_path, original_size, created_pcap)
            raise RepositoryError("metadata storage failed while saving packet") from exc
        except OSError as exc:
            self._rollback_pcap(pcap_path, original_size, created_pcap)
            raise RepositoryError("PCAP storage failed while saving packet") from exc

    @staticmethod
    def _rollback_pcap(path: Path, original_size: int, created: bool) -> None:
        try:
            if created:
                path.unlink(missing_ok=True)
            elif path.exists():
                with path.open("r+b") as stream:
                    stream.truncate(original_size)
        except OSError:
            # The original operation still reports failure; a later read will
            # detect any partial PCAP as corruption instead of hiding it.
            pass

    @staticmethod
    def _validate_query(
        protocol: str | None,
        address: str | None,
        time_window: Sequence[datetime | None] | None,
    ) -> tuple[str | None, str | None, int | None, int | None]:
        if protocol is not None and (not isinstance(protocol, str) or not protocol.strip()):
            raise InvalidRecordError("protocol filter must be a non-empty string or None")
        if address is not None and (not isinstance(address, str) or not address.strip()):
            raise InvalidRecordError("address filter must be a non-empty string or None")
        start_us = end_us = None
        if time_window is not None:
            if isinstance(time_window, (str, bytes)):
                raise InvalidRecordError("time_window must be a (start, end) pair")
            try:
                has_two_endpoints = len(time_window) == 2
            except TypeError as exc:
                raise InvalidRecordError("time_window must be a (start, end) pair") from exc
            if not has_two_endpoints:
                raise InvalidRecordError("time_window must be a (start, end) pair")
            start, end = time_window
            for endpoint in (start, end):
                if endpoint is not None:
                    if not isinstance(endpoint, datetime) or endpoint.tzinfo is None:
                        raise InvalidRecordError("time window endpoints must be timezone-aware datetimes or None")
                    try:
                        if endpoint.utcoffset() is None:
                            raise InvalidRecordError(
                                "time window endpoints must be timezone-aware datetimes or None"
                            )
                    except (OverflowError, OSError, ValueError, TypeError) as exc:
                        raise InvalidRecordError("time window endpoint has an invalid timezone") from exc
            if start is None and end is None:
                raise InvalidRecordError("time_window must include at least one endpoint")
            try:
                start_us = _timestamp_us(start) if start is not None else None
                end_us = _timestamp_us(end) if end is not None else None
            except (OverflowError, OSError, ValueError, TypeError) as exc:
                raise InvalidRecordError("time window endpoint is outside the supported range") from exc
            if start_us is not None and end_us is not None and start_us > end_us:
                raise InvalidRecordError("time window start must not be after end")
        return (
            protocol.strip().upper() if protocol is not None else None,
            address.strip() if address is not None else None,
            start_us,
            end_us,
        )

    def query(
        self,
        protocol: str | None = None,
        address: str | None = None,
        time_window: Sequence[datetime | None] | None = None,
        session_id: str | None = None,
    ) -> list[PacketRecord]:
        protocol, address, start_us, end_us = self._validate_query(protocol, address, time_window)
        if session_id is not None and (not isinstance(session_id, str) or not session_id.strip()):
            raise InvalidRecordError("session_id filter must be a non-empty string or None")
        clauses: list[str] = []
        params: list[object] = []
        if protocol is not None:
            clauses.append("p.protocol = ?")
            params.append(protocol)
        if session_id is not None:
            clauses.append("p.session_id = ?")
            params.append(session_id.strip())
        if address is not None:
            clauses.append("(p.source_address = ? OR p.destination_address = ?)")
            params.extend((address, address))
        if start_us is not None:
            clauses.append("p.timestamp_us >= ?")
            params.append(start_us)
        if end_us is not None:
            clauses.append("p.timestamp_us <= ?")
            params.append(end_us)
        sql = """SELECT p.*, c.pcap_name, c.link_type FROM packets p
                 JOIN captures c ON c.session_id = p.session_id"""
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY p.timestamp_us, p.record_id"
        try:
            with self._connection() as db:
                rows = db.execute(sql, params).fetchall()
            return [self._load_record(row) for row in rows]
        except PermissionError as exc:
            raise StorageAccessError("permission denied while querying captures") from exc
        except FileNotFoundError as exc:
            raise StorageUnavailableError("metadata or capture file is unavailable") from exc
        except sqlite3.Error as exc:
            raise RepositoryError("metadata query failed") from exc
        except OSError as exc:
            raise RepositoryError("PCAP read failed") from exc

    def _load_record(self, row: sqlite3.Row) -> PacketRecord:
        path = self._pcap_path(row["pcap_name"])
        try:
            with path.open("rb") as stream:
                header = stream.read(_GLOBAL_HEADER.size)
                if len(header) != _GLOBAL_HEADER.size:
                    raise StorageCorruptionError("PCAP global header is truncated")
                magic, major, minor, _, _, snaplen, link_type = _GLOBAL_HEADER.unpack(header)
                if (magic, major, minor) != (_PCAP_MAGIC, *_PCAP_VERSION) or link_type != row["link_type"]:
                    raise StorageCorruptionError("PCAP header is invalid or inconsistent")
                offset = row["pcap_offset"]
                file_size = path.stat().st_size
                if not isinstance(offset, int) or offset < _GLOBAL_HEADER.size:
                    raise StorageCorruptionError("metadata contains an invalid PCAP offset")
                if offset + _PACKET_HEADER.size > file_size:
                    raise StorageCorruptionError("PCAP packet offset is outside the capture file")
                stream.seek(offset)
                packet_header = stream.read(_PACKET_HEADER.size)
                if len(packet_header) != _PACKET_HEADER.size:
                    raise StorageCorruptionError("PCAP packet header is truncated")
                seconds, micros, captured, original = _PACKET_HEADER.unpack(packet_header)
                if (
                    captured != row["captured_length"] or original != row["original_length"]
                    or captured > snaplen or micros >= 1_000_000 or original < captured
                    or offset + _PACKET_HEADER.size + captured > file_size
                ):
                    raise StorageCorruptionError("PCAP packet header disagrees with metadata")
                data = stream.read(captured)
                if len(data) != captured:
                    raise StorageCorruptionError("PCAP packet data is truncated")
                timestamp = _from_timestamp_us(seconds * 1_000_000 + micros)
                if _timestamp_us(timestamp) != row["timestamp_us"]:
                    raise StorageCorruptionError("PCAP timestamp disagrees with metadata")
                try:
                    return PacketRecord(
                        record_id=row["record_id"], session_id=row["session_id"],
                        protocol=row["protocol"], source_address=row["source_address"],
                        destination_address=row["destination_address"], timestamp=timestamp,
                        packet_data=data, link_type=link_type, original_length=original,
                        interface=row["interface"],
                    )
                except InvalidRecordError as exc:
                    raise StorageCorruptionError("indexed packet metadata is malformed") from exc
        except PermissionError as exc:
            raise StorageAccessError(f"permission denied reading capture {path.name}") from exc
        except FileNotFoundError as exc:
            raise StorageUnavailableError(f"capture file is missing: {path.name}") from exc
        except (OverflowError, OSError, TypeError, ValueError, struct.error) as exc:
            raise StorageCorruptionError("PCAP record or indexed metadata is malformed") from exc

    def get_session_summary(self, session_id: str) -> SessionSummary:
        if not isinstance(session_id, str) or not session_id.strip():
            raise InvalidRecordError("session_id must be a non-empty string")
        try:
            with self._connection() as db:
                row = db.execute(
                    """SELECT COUNT(*) AS packet_count, MIN(timestamp_us) AS first_us,
                       MAX(timestamp_us) AS last_us FROM packets WHERE session_id = ?""",
                    (session_id,),
                ).fetchone()
            return SessionSummary(
                session_id=session_id,
                packet_count=row["packet_count"],
                first_packet_at=_from_timestamp_us(row["first_us"]) if row["first_us"] is not None else None,
                last_packet_at=_from_timestamp_us(row["last_us"]) if row["last_us"] is not None else None,
            )
        except PermissionError as exc:
            raise StorageAccessError("permission denied while reading session summary") from exc
        except sqlite3.Error as exc:
            raise RepositoryError("metadata summary query failed") from exc
        except OSError as exc:
            raise StorageUnavailableError("metadata database is unavailable") from exc
