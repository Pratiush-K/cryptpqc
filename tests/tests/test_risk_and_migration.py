import sys
from pathlib import Path

import pytest

from cryptpqc.risk import mosca
from cryptpqc.scanner import scan_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_migrated_app_scans_clean():
	assert scan_path(EXAMPLES / "legacy_app_migrated") == []


def test_migrated_app_still_works():
	sys.path.insert(0, str(EXAMPLES / "legacy_app_migrated"))
	import file_vault

	envelope = file_vault.encrypt_file_key(b"k" * 32)
	assert file_vault.decrypt_file_key(envelope) == b"k" * 32


def test_mosca_exposed_and_safe():
	assert mosca(25, 5, 10).exposed
	assert not mosca(2, 1, 10).exposed


def test_mosca_rejects_negative_numbers():
	with pytest.raises(ValueError):
		mosca(-1, 1, 1)
