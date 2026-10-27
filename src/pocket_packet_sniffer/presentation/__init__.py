"""Presentation-layer helpers for capture, statistics, and reports."""

from .capture_control import CaptureControl, CaptureControlError
from .capture_runner import (
    EXIT_CAPTURE_ERROR,
    EXIT_INTERRUPTED,
    EXIT_SUCCESS,
    run_capture_with_error_handling,
)
from .dashboard import render_stats, run_live_dashboard
from .report_export import ReportExportError, export_session_report_csv
from .report_pdf import export_session_report_pdf

__all__ = [
    "CaptureControl",
    "CaptureControlError",
    "EXIT_CAPTURE_ERROR",
    "EXIT_INTERRUPTED",
    "EXIT_SUCCESS",
    "ReportExportError",
    "export_session_report_csv",
    "export_session_report_pdf",
    "render_stats",
    "run_capture_with_error_handling",
    "run_live_dashboard",
]
