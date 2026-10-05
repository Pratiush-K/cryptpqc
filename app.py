"""Crypt web server: serves the HTML/CSS/JS front end and a small JSON API.

The API is a thin wrapper over the same backend the CLI uses
(cryptpqc.scanner, cryptpqc.risk, cryptpqc.api, cryptpqc.bench).
Run:  python app.py   then open http://localhost:5000
"""
from __future__ import annotations

import base64
import io
import json
import os
import tempfile
import time
import zipfile
from dataclasses import asdict, replace
from pathlib import Path

from cryptography.exceptions import InvalidTag
from flask import Flask, jsonify, request, send_from_directory

from cryptpqc import assistant
from cryptpqc import Envelope, __version__, crypt_decrypt, crypt_encrypt, crypt_keygen
from cryptpqc.risk import mosca
from cryptpqc.scanner import SCAN_EXTENSIONS, SKIP_DIRS, risk_label, risk_score, scan_path
from cryptpqc.shor_demo import (
	make_toy_rsa,
	recover_private_exponent,
	rsa_decrypt_text,
	rsa_encrypt_text,
	shor_factor,
)
from cryptpqc.tls_scan import EndpointError, scan_endpoint

ROOT = Path(__file__).parent
assistant.load_dotenv(ROOT / ".env")  # GROQ_API_KEY for "Ask Crypt"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_ZIP_MEMBERS = 5000
# Local testing only: lets /api/endpoint scan localhost and private addresses.
ALLOW_PRIVATE_ENDPOINTS = os.environ.get("CRYPT_ALLOW_PRIVATE") == "1"

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


# ---------------------------------------------------------------- helpers
def safe_extract_zip(data: bytes, dest: Path) -> None:
	"""Extract a zip, refusing path traversal and zip bombs."""
	dest = dest.resolve()
	with zipfile.ZipFile(io.BytesIO(data)) as zf:
		members = zf.infolist()
		if len(members) > MAX_ZIP_MEMBERS:
			raise ValueError(f"Zip has more than {MAX_ZIP_MEMBERS} entries.")
		if sum(m.file_size for m in members) > MAX_UPLOAD_BYTES:
			raise ValueError("Zip expands to more than 50 MB.")
		for m in members:
			target = (dest / m.filename).resolve()
			if dest not in target.parents:
				continue
			if m.is_dir():
				target.mkdir(parents=True, exist_ok=True)
				continue
			target.parent.mkdir(parents=True, exist_ok=True)
			target.write_bytes(zf.read(m))


def count_scannable(root: Path) -> int:
	return sum(
		1
		for p in root.rglob("*")
		if p.is_file()
		and p.suffix.lower() in SCAN_EXTENSIONS
		and not any(part in SKIP_DIRS for part in p.relative_to(root).parts)
	)


def preview(b: bytes, n: int = 24) -> str:
	h = b.hex()
	return h if len(h) <= n * 2 else f"{h[: n * 2]}…"


def bad(msg: str, code: int = 400):
	return jsonify({"error": msg}), code


@app.after_request
def cors(resp):
	"""Allow the front end to be opened from another local port (e.g. VS Code Live Server)."""
	if request.path.startswith(("/api/", "/docs/")):
		resp.headers["Access-Control-Allow-Origin"] = "*"
		resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
	return resp


@app.route("/api/<path:_>", methods=["OPTIONS"])
def preflight(_):
	return ("", 204)


# Simple per-IP limiter so the chat endpoint can't burn through the Groq key.
_ASK_WINDOW, _ASK_LIMIT = 60.0, 15
_ask_hits: dict[str, list[float]] = {}


def _ask_allowed(ip: str) -> bool:
	now = time.monotonic()
	hits = [t for t in _ask_hits.get(ip, []) if now - t < _ASK_WINDOW]
	if len(hits) >= _ASK_LIMIT:
		_ask_hits[ip] = hits
		return False
	hits.append(now)
	_ask_hits[ip] = hits
	if len(_ask_hits) > 1000:  # drop idle clients
		for k in [k for k, v in _ask_hits.items() if not v or now - v[-1] >= _ASK_WINDOW]:
			del _ask_hits[k]
	return True


# ---------------------------------------------------------------- pages
@app.get("/")
def index():
	return send_from_directory(ROOT / "web", "index.html")


@app.get("/<path:name>")
def static_files(name: str):
	if name in ("style.css", "app.js"):
		return send_from_directory(ROOT / "web", name)
	if name == "docs/benchmarks.png":
		return send_from_directory(ROOT / "docs", "benchmarks.png")
	return bad("Not found", 404)


# ---------------------------------------------------------------- API
@app.get("/api/info")
def info():
	return jsonify({"version": __version__, "extensions": sorted(SCAN_EXTENSIONS)})


@app.post("/api/scan")
def api_scan():
	uploads = request.files.getlist("files")
	if not uploads:
		return bad("No files uploaded.")
	try:
		with tempfile.TemporaryDirectory() as tmp:
			root = Path(tmp)
			for i, up in enumerate(uploads):
				name = Path(up.filename or f"file{i}").name
				data = up.read()
				if name.lower().endswith(".zip"):
					safe_extract_zip(data, root / f"z{i}")
				else:
					(root / f"f{i}").mkdir()
					(root / f"f{i}" / name).write_bytes(data)
			scanned = count_scannable(root)
			findings = []
			for f in scan_path(root):
				rel = Path(f.file).relative_to(root).parts[1:]  # drop our wrapper folder
				findings.append(replace(f, file="/".join(rel)))
	except (zipfile.BadZipFile, ValueError) as err:
		return bad(f"Could not read upload: {err}")
	score = risk_score(findings)
	return jsonify(
		{
			"findings": [asdict(f) for f in findings],
			"score": score,
			"label": risk_label(score),
			"scanned": scanned,
		}
	)


@app.post("/api/endpoint")
def api_endpoint():
	"""Scan a live TLS endpoint, e.g. {"target": "example.com"}."""
	body = request.get_json(silent=True) or {}
	try:
		report = scan_endpoint(str(body.get("target", "")), allow_private=ALLOW_PRIVATE_ENDPOINTS)
	except EndpointError as err:
		return bad(str(err), err.status)
	return jsonify(asdict(report))


@app.post("/api/ask")
def api_ask():
	"""Ask Crypt: {"question", "history": [...], "context": {"scan", "site", "mosca"}}."""
	if not _ask_allowed(request.remote_addr or "?"):
		return bad("Too many questions. Wait a minute and try again.", 429)
	body = request.get_json(silent=True) or {}
	try:
		return jsonify(
			assistant.ask(str(body.get("question", "")), body.get("history"), body.get("context"))
		)
	except assistant.AssistantError as err:
		return bad(str(err), err.status)


@app.get("/api/ask/status")
def api_ask_status():
	return jsonify({"configured": bool(os.environ.get("GROQ_API_KEY", "").strip())})


@app.post("/api/mosca")
def api_mosca():
	body = request.get_json(silent=True) or {}
	try:
		r = mosca(
			float(body["shelf_life"]), float(body["migration_time"]), float(body["years_to_threat"])
		)
	except (KeyError, TypeError, ValueError) as err:
		return bad(f"Invalid input: {err}")
	out = asdict(r)
	out["verdict"] = out["verdict"].replace("-0.0 ", "0.0 ")
	return jsonify(out)


@app.post("/api/shor")
def api_shor():
	body = request.get_json(silent=True) or {}
	try:
		bits = int(body.get("bits", 20))
		seed = int(body.get("seed", 1))
		message = str(body.get("message", ""))[:48] or "hello"
		key = make_toy_rsa(bits, seed)
	except (TypeError, ValueError) as err:
		return bad(str(err))
	blocks = rsa_encrypt_text(key, message)
	result = shor_factor(key.n, seed=seed)
	out = {
		"n": key.n,
		"e": key.e,
		"ciphertext": blocks,
		"attempts": [asdict(a) for a in result.attempts],
		"success": result.success,
		"seconds": result.seconds,
	}
	if result.success:
		d = recover_private_exponent(result.p, result.q, key.e)
		out.update(
			p=result.p, q=result.q, d=d, recovered=rsa_decrypt_text(key.n, d, blocks)
		)
	return jsonify(out)


@app.post("/api/hybrid")
def api_hybrid():
	"""Generate a hybrid keypair, encrypt, optionally tamper, then decrypt."""
	body = request.get_json(silent=True) or {}
	message = str(body.get("message", "")).encode("utf-8")[:4096]
	pub, priv = crypt_keygen()
	env = crypt_encrypt(pub, message)
	sent = env
	if body.get("tamper") and env.ciphertext:
		ct = bytearray(env.ciphertext)
		ct[0] ^= 1
		sent = Envelope(env.eph_pub, env.pq_ct, env.nonce, bytes(ct))
	out = {
		"keys": {
			"x25519_public": len(pub.x25519),
			"mlkem_public": len(pub.mlkem),
			"x25519_private": len(priv.x25519),
			"mlkem_private": len(priv.mlkem),
		},
		"envelope": [
			{"field": "Ephemeral X25519 key", "size": len(env.eph_pub), "preview": preview(env.eph_pub)},
			{"field": "ML-KEM-768 ciphertext", "size": len(env.pq_ct), "preview": preview(env.pq_ct)},
			{"field": "AES-GCM nonce", "size": len(env.nonce), "preview": preview(env.nonce)},
			{"field": "AES-GCM ciphertext", "size": len(env.ciphertext), "preview": preview(env.ciphertext)},
		],
	}
	try:
		out["decrypted"] = crypt_decrypt(priv, sent).decode("utf-8", errors="replace")
	except InvalidTag:
		out["error"] = "Decryption refused: the ciphertext was modified (authentication tag mismatch)."
	return jsonify(out)


@app.post("/api/bench")
def api_bench():
	from cryptpqc.bench import run_benchmarks, save_chart

	body = request.get_json(silent=True) or {}
	iterations = max(3, min(int(body.get("iterations", 10)), 50))
	data = run_benchmarks(iterations=iterations)
	with tempfile.TemporaryDirectory() as tmp:
		save_chart(data, Path(tmp) / "b.png")
		png = base64.b64encode((Path(tmp) / "b.png").read_bytes()).decode()
	return jsonify({"data": data, "chart": f"data:image/png;base64,{png}", "live": True})


@app.get("/api/bench/saved")
def api_bench_saved():
	path = ROOT / "docs" / "benchmarks.json"
	if not path.exists():
		return bad("No saved benchmarks.", 404)
	return jsonify({"data": json.loads(path.read_text("utf-8")), "chart": "/docs/benchmarks.png", "live": False})


if __name__ == "__main__":
	app.run(debug=False, port=5000)
