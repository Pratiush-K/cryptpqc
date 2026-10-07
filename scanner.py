"""Find quantum-vulnerable cryptography in source code."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".json", ".yml", ".yaml"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist"}
WEIGHTS = {"HIGH": 10, "MEDIUM": 4, "LOW": 1}


@dataclass(frozen=True)
class Rule:
	rule_id: str
	algorithm: str
	pattern: re.Pattern
	severity: str
	why: str
	fix: str


@dataclass(frozen=True)
class Finding:
	file: str
	line: int
	rule_id: str
	algorithm: str
	severity: str
	code: str
	why: str
	fix: str


def _rx(pattern: str) -> re.Pattern:
	return re.compile(pattern, re.IGNORECASE)


RULES = [
	Rule(
		"RSA-001",
		"RSA",
		_rx(
			r"rsa\.generate_private_key|RSA\.generate\(|rsa\.newkeys\(|RSA\.import_?key"
			r"|getInstance\(.RSA.\)|padding\.OAEP|PKCS1v15|PKCS1_OAEP"
		),
		"HIGH",
		"Shor's algorithm can factor RSA keys on a large quantum computer.",
		"Use ML-KEM-768 (FIPS 203) via crypt_encrypt, hybrid with X25519 during migration",
	),
	Rule(
		"RSA-002",
		"RSA (JWT signature)",
		_rx(r"\b(?:RS|PS)(?:256|384|512)\b"),
		"HIGH",
		"RSA signatures can be forged once RSA is broken.",
		"Use ML-DSA (FIPS 204) signatures, or a hybrid scheme during migration",
	),
	Rule(
		"ECC-001",
		"Elliptic curve",
		_rx(
			r"ec\.generate_private_key|ec\.SECP\d+R1|\bECDSA\b|\bECDH\b"
			r"|\bES(?:256|384|512)\b|Ed25519|X25519|secp256k1|prime256v1"
		),
		"HIGH",
		"Shor's algorithm also solves the elliptic-curve discrete log problem.",
		"Use ML-KEM-768 for key exchange and ML-DSA for signatures",
	),
	Rule(
		"DH-001",
		"Diffie-Hellman",
		_rx(r"dh\.generate_parameters|DiffieHellman|createDiffieHellman|\bDHE\b"),
		"HIGH",
		"Finite-field Diffie-Hellman falls to Shor's algorithm.",
		"Use ML-KEM-768 key exchange",
	),
	Rule(
		"HASH-001",
		"MD5 / SHA-1",
		_rx(r"hashlib\.(?:md5|sha1)\(|MessageDigest\.getInstance\(.(?:MD5|SHA-?1).\)"),
		"MEDIUM",
		"Already broken by classical collision attacks (not a quantum issue).",
		"Use SHA-256 or SHA-3",
	),
]


def _iter_files(root: Path):
	if root.is_file():
		yield root
		return
	for dirpath, dirnames, filenames in os.walk(root):
		dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
		for name in sorted(filenames):
			yield Path(dirpath) / name


def _scan_file(path: Path) -> list[Finding]:
	try:
		text = path.read_text(encoding="utf-8")
	except (UnicodeDecodeError, OSError):
		return []
	results = []
	for lineno, line in enumerate(text.splitlines(), start=1):
		for rule in RULES:
			if rule.pattern.search(line):
				results.append(
					Finding(
						file=str(path),
						line=lineno,
						rule_id=rule.rule_id,
						algorithm=rule.algorithm,
						severity=rule.severity,
						code=line.strip(),
						why=rule.why,
						fix=rule.fix,
					)
				)
	return results


def scan_path(root: str | Path) -> list[Finding]:
	"""Scan a file or folder and return every vulnerable-crypto finding."""
	root = Path(root)
	if not root.exists():
		raise FileNotFoundError(f"Path not found: {root}")
	findings: list[Finding] = []
	for path in _iter_files(root):
		if path.suffix.lower() in SCAN_EXTENSIONS:
			findings.extend(_scan_file(path))
	return findings


def risk_score(findings: list[Finding]) -> int:
	"""Simple heuristic: weighted count of findings, capped at 100."""
	return min(100, sum(WEIGHTS[f.severity] for f in findings))


def risk_label(score: int) -> str:
	if score == 0:
		return "CLEAN"
	if score < 20:
		return "LOW"
	if score < 50:
		return "MEDIUM"
	return "HIGH"
