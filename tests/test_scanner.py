from pathlib import Path

from cryptpqc.scanner import risk_label, risk_score, scan_path

LEGACY = Path(__file__).resolve().parent.parent / "examples" / "legacy_app"


def test_scanner_finds_vulnerable_crypto():
	findings = scan_path(LEGACY)
	algorithms = {f.algorithm for f in findings}
	assert "RSA" in algorithms
	assert "Elliptic curve" in algorithms
	assert any(f.severity == "HIGH" for f in findings)


def test_clean_folder_has_no_findings(tmp_path):
	(tmp_path / "ok.py").write_text("print('hello')\n")
	assert scan_path(tmp_path) == []


def test_risk_score_and_label():
	score = risk_score(scan_path(LEGACY))
	assert 0 < score <= 100
	assert risk_label(score) in {"MEDIUM", "HIGH"}
