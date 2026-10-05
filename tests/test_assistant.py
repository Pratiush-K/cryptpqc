import io
import json
import urllib.error

import pytest

import app as crypt_app
from cryptpqc import assistant

SCAN = {
	"score": 24, "label": "MEDIUM", "scanned": 3,
	"findings": [
		{"file": "auth_service.py", "line": 12, "rule_id": "RSA-KEYGEN", "algorithm": "RSA", "severity": "HIGH",
		 "code": "rsa.generate_private_key(...)", "why": "Shor breaks RSA", "fix": "Use ML-KEM-768 + X25519"},
	],
}
SITE = {"host": "example.com", "port": 443, "score": 40, "label": "MEDIUM", "verdict": "Classical only",
		"tls_version": "TLSv1.3", "cipher": "AES256", "key_exchange": "X25519",
		"pq_groups": {"X25519MLKEM768": False, "X25519Kyber768Draft00": False},
		"cert": None, "findings": [], "strengths": []}


def test_prompt_contains_user_data():
	p = assistant.build_system_prompt({"scan": SCAN, "site": SITE, "mosca": {"shelf_life": 10, "migration_time": 5, "years_to_threat": 12}})
	assert "auth_service.py:12" in p and "RSA-KEYGEN" in p
	assert "example.com" in p and "X25519MLKEM768" in p
	assert "EXPOSED by 3.0 yr" in p  # recomputed server-side


def test_prompt_handles_missing_and_garbage_context():
	p = assistant.build_system_prompt({"scan": "x", "site": 5, "mosca": {"shelf_life": "abc"}})
	assert "not run yet" in p and "no valid values" in p
	assert "not run yet" in assistant.build_system_prompt(None)


def test_findings_capped():
	many = {"score": 100, "label": "HIGH", "scanned": 1,
			"findings": [dict(SCAN["findings"][0], line=i) for i in range(100)]}
	assert "+60 lower-severity" in assistant.describe_scan(many)


def test_history_sanitised():
	msgs = assistant.build_messages("q", [{"role": "system", "content": "evil"}, {"role": "user", "content": "ok"}, 5], {})
	assert [m["role"] for m in msgs] == ["system", "user", "user"]


class FakeResp(io.BytesIO):
	def __enter__(self): return self
	def __exit__(self, *a): return False


def test_ask_calls_groq(monkeypatch):
	monkeypatch.setenv("GROQ_API_KEY", "k")
	seen = {}

	def fake(req, timeout):
		seen["auth"] = req.get_header("Authorization")
		seen["body"] = json.loads(req.data)
		return FakeResp(json.dumps({"choices": [{"message": {"content": " hi "}}]}).encode())

	monkeypatch.setattr(assistant.urllib.request, "urlopen", fake)
	out = assistant.ask("Why HIGH?", [], {"scan": SCAN})
	assert out["answer"] == "hi"
	assert seen["auth"] == "Bearer k"
	assert "auth_service.py" in seen["body"]["messages"][0]["content"]
	assert seen["body"]["messages"][-1] == {"role": "user", "content": "Why HIGH?"}


def test_missing_key_and_bad_input(monkeypatch):
	monkeypatch.delenv("GROQ_API_KEY", raising=False)
	with pytest.raises(assistant.AssistantError) as e:
		assistant.ask("hello")
	assert e.value.status == 503
	with pytest.raises(assistant.AssistantError):
		assistant.ask("   ")


def test_groq_errors_mapped(monkeypatch):
	monkeypatch.setenv("GROQ_API_KEY", "k")
	def boom(code):
		def f(req, timeout):
			raise urllib.error.HTTPError("u", code, "x", {}, None)
		return f
	for code, status in ((401, 502), (429, 429), (500, 502)):
		monkeypatch.setattr(assistant.urllib.request, "urlopen", boom(code))
		with pytest.raises(assistant.AssistantError) as e:
			assistant.ask("q")
		assert e.value.status == status


def test_endpoint(monkeypatch):
	monkeypatch.setenv("GROQ_API_KEY", "k")
	monkeypatch.setattr(assistant, "ask", lambda q, h, c: {"answer": "yo", "model": "m"})
	crypt_app._ask_hits.clear()
	c = crypt_app.app.test_client()
	assert c.post("/api/ask", json={"question": "hi"}).get_json()["answer"] == "yo"
	assert c.get("/api/ask/status").get_json() == {"configured": True}
	crypt_app._ask_hits.clear()
	for _ in range(15):
		c.post("/api/ask", json={"question": "hi"})
	assert c.post("/api/ask", json={"question": "hi"}).status_code == 429
	crypt_app._ask_hits.clear()


def test_dotenv(tmp_path, monkeypatch):
	f = tmp_path / ".env"
	f.write_text('# c\nGROQ_API_KEY="abc"\nexport FOO_X=1\n')
	monkeypatch.delenv("GROQ_API_KEY", raising=False)
	monkeypatch.delenv("FOO_X", raising=False)
	assistant.load_dotenv(f)
	import os
	assert os.environ["GROQ_API_KEY"] == "abc" and os.environ["FOO_X"] == "1"
	monkeypatch.delenv("FOO_X")
