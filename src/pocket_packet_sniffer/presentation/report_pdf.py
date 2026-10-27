"""Generate local, metadata-only PDF session reports using the standard library."""
from __future__ import annotations

import os
import textwrap
from pathlib import Path
from typing import Iterable

from pocket_packet_sniffer.presentation.report_export import ReportExportError
from pocket_packet_sniffer.storage.models import PacketRecord, SessionSummary


def _pdf_text(value: object) -> str:
    """Return PDF literal-string-safe ASCII without including packet payloads."""
    text = str(value).encode("ascii", "replace").decode("ascii")
    text = text.replace("\\r", " ").replace("\\n", " ").replace("\\t", " ")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_pdf(lines: list[str]) -> bytes:
    width = 98
    wrapped: list[str] = []
    for line in lines:
        pieces = textwrap.wrap(line, width=width, break_long_words=True, break_on_hyphens=False)
        wrapped.extend(pieces or [""])
    per_page = 48
    pages = [wrapped[offset : offset + per_page] for offset in range(0, len(wrapped), per_page)] or [[]]

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",  # filled after page objects are created
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    page_ids: list[int] = []
    for page_lines in pages:
        page_id = len(objects) + 1
        content_id = page_id + 1
        page_ids.append(page_id)
        commands: list[str] = []
        for index, line in enumerate(page_lines):
            y = 760 - index * 14
            commands.append(f"BT /F1 9 Tf 36 {y} Td ({_pdf_text(line)}) Tj ET")
        stream = ("\n".join(commands) + "\n").encode("ascii")
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
            ).encode("ascii")
        )
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream
            + b"endstream"
        )
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def export_session_report_pdf(
    summary: SessionSummary,
    records: Iterable[PacketRecord],
    destination: str | os.PathLike[str],
) -> Path:
    """Write session summary and packet metadata as a new, local PDF file."""
    if not isinstance(summary, SessionSummary):
        raise ReportExportError("summary must be a SessionSummary")
    try:
        path = Path(destination).expanduser()
    except (TypeError, ValueError, OSError) as exc:
        raise ReportExportError("invalid report output path") from exc
    if path.is_dir():
        raise ReportExportError(f"could not write report to '{path}': destination is a directory")
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

    def timestamp(value: object) -> str:
        return value.isoformat() if value is not None else ""

    lines = [
        "POCKET PACKET SNIFFER - CAPTURE SESSION REPORT",
        f"Session: {summary.session_id}",
        f"Packets stored: {summary.packet_count}",
        f"First packet: {timestamp(summary.first_packet_at) or 'N/A'}",
        f"Last packet: {timestamp(summary.last_packet_at) or 'N/A'}",
        "",
        "PACKET METADATA (payload bytes are intentionally excluded)",
    ]
    for record in stored_records:
        lines.append(
            f"{record.timestamp.isoformat()} | {record.protocol} | "
            f"{record.source_address or '-'} -> {record.destination_address or '-'} | "
            f"{len(record.packet_data)}/{record.original_length} bytes | "
            f"{record.interface or '-'} | {record.capture_backend or '-'}"
        )
    if not stored_records:
        lines.append("No packet records were stored in this session.")

    pdf = _build_pdf(lines)
    try:
        with path.open("xb") as stream:
            stream.write(pdf)
    except FileExistsError as exc:
        raise ReportExportError(f"report already exists; choose another path: {path}") from exc
    except (IsADirectoryError, PermissionError, OSError) as exc:
        raise ReportExportError(f"could not write report to '{path}': {exc}") from exc
    return path
