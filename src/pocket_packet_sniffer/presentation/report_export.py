"""Export stored capture-session summaries as local CSV reports.

This module accepts session data from the storage/query layer; it does not
start capture or access a live capture backend.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Iterable

from pocket_packet_sniffer.storage.models import PacketRecord, SessionSummary


class ReportExportError(Exception):
    """A report could not be validated or written to the requested path."""


_FIELDS = (
    "session_id",
    "packet_count",
    "first_packet_at",
    "last_packet_at",
    "record_id",
    "timestamp",
    "protocol",
    "source_address",
    "destination_address",
    "interface",
    "capture_backend",
    "captured_length",
    "original_length",
)


def export_session_report_csv(
    summary: SessionSummary,
    records: Iterable[PacketRecord],
    destination: str | os.PathLike[str],
) -> Path:
    """Write a session summary and its stored packet metadata to a new CSV.

    Existing files are never overwritten. For an empty session, one summary
    row is written with blank packet-specific fields.
    """
    if not isinstance(summary, SessionSummary):
        raise ReportExportError("summary must be a SessionSummary")
    try:
        path = Path(destination).expanduser()
    except (TypeError, ValueError, OSError) as exc:
        raise ReportExportError("invalid report output path") from exc

    if path.is_dir():
        raise ReportExportError("could not write report to '" + str(path) + "': destination is a directory")

    try:
        stored_records = list(records)
    except (TypeError, ValueError) as exc:
        raise ReportExportError("records must be an iterable of stored PacketRecord values") from exc

    if any(not isinstance(record, PacketRecord) for record in stored_records):
        raise ReportExportError("records must contain only PacketRecord values")
    if any(record.session_id != summary.session_id for record in stored_records):
        raise ReportExportError("all records must belong to the requested session")
    if len(stored_records) != summary.packet_count:
        raise ReportExportError(
            f"session summary reports {summary.packet_count} packets but "
            f"{len(stored_records)} records were supplied"
        )

    def timestamp(value):
        return value.isoformat() if value is not None else ""

    rows = []
    for record in stored_records:
        rows.append({
            "session_id": summary.session_id,
            "packet_count": summary.packet_count,
            "first_packet_at": timestamp(summary.first_packet_at),
            "last_packet_at": timestamp(summary.last_packet_at),
            "record_id": record.record_id,
            "timestamp": timestamp(record.timestamp),
            "protocol": record.protocol,
            "source_address": record.source_address or "",
            "destination_address": record.destination_address or "",
            "interface": record.interface or "",
            "capture_backend": record.capture_backend or "",
            "captured_length": len(record.packet_data),
            "original_length": record.original_length,
        })
    if not rows:
        rows.append({
            "session_id": summary.session_id,
            "packet_count": summary.packet_count,
            "first_packet_at": timestamp(summary.first_packet_at),
            "last_packet_at": timestamp(summary.last_packet_at),
            "record_id": "",
            "timestamp": "",
            "protocol": "",
            "source_address": "",
            "destination_address": "",
            "interface": "",
            "capture_backend": "",
            "captured_length": "",
            "original_length": "",
        })

    try:
        # "x" uses exclusive creation and prevents accidental overwrites.
        with path.open("x", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    except FileExistsError as exc:
        raise ReportExportError(f"report already exists; choose another path: {path}") from exc
    except (IsADirectoryError, PermissionError, OSError) as exc:
        raise ReportExportError(f"could not write report to '{path}': {exc}") from exc

    return path
