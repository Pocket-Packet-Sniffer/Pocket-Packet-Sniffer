from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANALYSIS_PATH = ROOT / "src" / "pocket_packet_sniffer" / "analysis"


def test_analysis_layer_does_not_import_storage_implementation():
    """Architecture check: Analysis may depend on Capture, not concrete Storage."""
    for module in ANALYSIS_PATH.glob("*.py"):
        source = module.read_text(encoding="utf-8")
        assert "pocket_packet_sniffer.storage" not in source, module.name
        assert "from ..storage" not in source, module.name
