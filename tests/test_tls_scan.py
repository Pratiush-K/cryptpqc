import datetime
import socket
import ssl
import struct
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from cryptpqc import tls_scan
from cryptpqc.tls_scan import (
    DRAFT_GROUP,
    HRR_RANDOM,
    STD_GROUP,
    EndpointError,
    assess,
    build_client_hello,
    key_exchange_family,
    parse_server_reply,
    parse_target,
    probe_group,
    scan_endpoint,
)


# ---------------------------------------------------------------- helpers
def _u16(n):
    return struct.pack("!H", n)


def fake_server_hello(group, retry=False, tls13=True):
    """Build a ServerHello (or HelloRetryRequest) record like a real server would send."""
    exts = b""
    if tls13:
        exts += _u16(0x002B) + _u16(2) + b"\x03\x04"
    exts += _u16(0x0033) + (_u16(2) + _u16(group) if retry else _u16(4) + _u16(group) + _u16(0))
    body = (
        b"\x03\x03" + (HRR_RANDOM if retry else b"\x11" * 32)
        + b"\x20" + b"\x22" * 32 + _u16(0x1301) + b"\x00" + _u16(len(exts)) + exts
    )
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + _u16(len(hs)) + hs


def fake_alert(code):
    return b"\x15\x03\x03\x00\x02\x02" + bytes([code])


@contextmanager
def fake_tls_server(reply):
    """A TCP server that reads one ClientHello and answers with fixed bytes."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)

    def run():
        try:
            conn, _ = srv.accept()
            with conn:
                conn.recv(4096)
                conn.sendall(reply)
        except OSError:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    try:
        yield srv.getsockname()[1]
    finally:
        srv.close()
        t.join(timeout=2)


def make_cert(key, days=30, hash_alg=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crypt-test.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("crypt-test.local")]), critical=False)
        .sign(key, hash_alg or hashes.SHA256())
    )
    return cert


@contextmanager
def local_tls_server(key, max_version=None):
    """A real TLS server on localhost using a self-signed certificate."""
    cert = make_cert(key)
    with tempfile.TemporaryDirectory() as tmp:
        cert_path, key_path = Path(tmp, "c.pem"), Path(tmp, "k.pem")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        if max_version:
            ctx.maximum_version = max_version
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.2)
        stop = threading.Event()

        def run():
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except OSError:
                    continue
                conn.settimeout(3)
                try:
                    ctx.wrap_socket(conn, server_side=True).close()
                except (ssl.SSLError, OSError):
                    conn.close()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        try:
            yield srv.getsockname()[1]
        finally:
            stop.set()
            t.join(timeout=2)
            srv.close()


def cert_info(key_type="ECDSA", bits=256, sig_hash="sha256", days_left=60):
    return {
        "key_type": key_type, "key_bits": bits, "key_detail": f"{bits}-bit", "sig_hash": sig_hash,
        "days_left": days_left, "subject": "x", "issuer": "y", "self_signed": False, "names": [],
    }


def rule_ids(findings):
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------- input parsing
def test_parse_target_accepts_common_forms():
    assert parse_target("Example.com") == ("example.com", None)
    assert parse_target("https://example.com/some/path?q=1") == ("example.com", None)
    assert parse_target("example.com:8443") == ("example.com", 8443)
    assert parse_target("  example.com.  ") == ("example.com", None)
    assert parse_target("8.8.8.8") == ("8.8.8.8", None)
    assert parse_target("https://[2001:4860:4860::8888]:443/") == ("2001:4860:4860::8888", 443)


def test_parse_target_rejects_garbage():
    for bad in ["", "   ", "not a host", "exa mple.com", "a" * 400, "https://", "example.com:99999"]:
        try:
            parse_target(bad)
        except EndpointError:
            continue
        raise AssertionError(f"accepted {bad!r}")


# ---------------------------------------------------------------- SSRF protection
def test_private_and_local_addresses_are_blocked():
    for target in [
        "127.0.0.1", "localhost", "10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.169.254",
        "0.0.0.0", "100.64.0.1", "[::1]", "[::ffff:127.0.0.1]", "[fe80::1]", "224.0.0.1",
    ]:
        try:
            scan_endpoint(target)
        except EndpointError as err:
            assert "public" in str(err), (target, str(err))
        else:
            raise AssertionError(f"scanned {target}")


def test_unusual_ports_are_blocked():
    try:
        scan_endpoint("example.com:22")
    except EndpointError as err:
        assert "Port 22" in str(err)
    else:
        raise AssertionError("port 22 was allowed")


# ---------------------------------------------------------------- packet building and parsing
def test_client_hello_is_well_formed():
    data = build_client_hello("example.com", 0x11EC)
    assert data[0] == 0x16
    record_len = struct.unpack_from("!H", data, 3)[0]
    assert record_len == len(data) - 5
    assert data[5] == 0x01  # ClientHello
    handshake_len = int.from_bytes(data[6:9], "big")
    assert handshake_len == record_len - 4
    assert b"example.com" in data
    assert b"\x00\x0a\x00\x04\x00\x02\x11\xec" in data  # supported_groups = [0x11EC]
    assert data.endswith(b"\x00\x33\x00\x02\x00\x00")  # empty key_share


def test_client_hello_omits_sni_for_ip_literals():
    name = "example.com"
    with_sni = build_client_hello(name, 0x11EC)
    without = build_client_hello(None, 0x11EC)
    assert len(with_sni) - len(without) == len(name) + 9  # extension header, list header, name
    assert name.encode() not in without


def test_parse_server_reply_variants():
    assert parse_server_reply(fake_server_hello(0x11EC, retry=True)) == ("hello_retry", 0x11EC)
    assert parse_server_reply(fake_server_hello(0x001D)) == ("server_hello", 0x001D)
    assert parse_server_reply(fake_server_hello(0x001D, tls13=False)) == ("tls12", None)
    assert parse_server_reply(fake_alert(40)) == ("alert", 40)
    assert parse_server_reply(b"") == ("unknown", None)
    assert parse_server_reply(b"HTTP/1.1 400 Bad Request\r\n") == ("unknown", None)
    assert parse_server_reply(fake_server_hello(0x11EC, retry=True)[:20]) == ("unknown", None)


def test_probe_group_reads_each_kind_of_reply():
    with fake_tls_server(fake_server_hello(0x11EC, retry=True)) as port:
        assert probe_group("127.0.0.1", port, "x.test", 0x11EC, 3) is True
    with fake_tls_server(fake_alert(40)) as port:
        assert probe_group("127.0.0.1", port, "x.test", 0x11EC, 3) is False
    with fake_tls_server(fake_server_hello(0x001D, tls13=False)) as port:
        assert probe_group("127.0.0.1", port, "x.test", 0x11EC, 3) is False
    with fake_tls_server(fake_alert(80)) as port:  # internal_error: unclear, not a refusal
        assert probe_group("127.0.0.1", port, "x.test", 0x11EC, 3) is None
    with fake_tls_server(b"") as port:  # connection closed with no reply
        assert probe_group("127.0.0.1", port, "x.test", 0x11EC, 3) is None


def test_probe_group_returns_none_when_nothing_listens():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert probe_group("127.0.0.1", port, None, 0x11EC, 1) is None


# ---------------------------------------------------------------- assessment
def test_key_exchange_family():
    assert key_exchange_family("TLSv1.3", "TLS_AES_256_GCM_SHA384") == "ECDHE (TLS 1.3)"
    assert key_exchange_family("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256") == "ECDHE"
    assert key_exchange_family("TLSv1.2", "DHE-RSA-AES256-SHA") == "DHE"
    assert key_exchange_family("TLSv1.2", "AES256-GCM-SHA384") == "RSA key transport"


def test_assess_classical_only_is_high_risk():
    f, strengths, verdict, kind = assess(
        "TLSv1.3", "ECDHE (TLS 1.3)", {STD_GROUP: False, DRAFT_GROUP: False}, cert_info()
    )
    assert "KEX-001" in rule_ids(f) and kind == "err" and not strengths
    assert sum(x.points for x in f) == 70
    assert "harvest-now-decrypt-later" in verdict


def test_assess_hybrid_with_ecdsa_cert_is_low_risk():
    f, strengths, _, kind = assess(
        "TLSv1.3", "ECDHE (TLS 1.3)", {STD_GROUP: True, DRAFT_GROUP: False}, cert_info()
    )
    assert rule_ids(f) == {"CERT-001"} and kind == "ok" and strengths
    assert sum(x.points for x in f) == 10


def test_assess_draft_only_and_inconclusive():
    f, _, _, kind = assess("TLSv1.3", "ECDHE (TLS 1.3)", {STD_GROUP: False, DRAFT_GROUP: True}, None)
    assert rule_ids(f) == {"KEX-002"} and kind == "info"
    f, _, _, kind = assess("TLSv1.3", "ECDHE (TLS 1.3)", {STD_GROUP: None, DRAFT_GROUP: None}, None)
    assert rule_ids(f) == {"KEX-004"} and kind == "info"


def test_assess_legacy_problems():
    pq = {STD_GROUP: False, DRAFT_GROUP: False}
    f, *_ = assess("TLSv1", "RSA key transport", pq, cert_info("RSA", 1024, "sha1", -3))
    assert rule_ids(f) >= {"KEX-001", "KEX-003", "VER-001", "CERT-002", "CERT-003", "CERT-004"}
    f, *_ = assess("TLSv1.2", "ECDHE", pq, cert_info("RSA", 2048))
    assert "VER-002" in rule_ids(f) and "CERT-002" not in rule_ids(f)


# ---------------------------------------------------------------- real servers on localhost
def test_scan_tls13_server_with_ecdsa_cert():
    with local_tls_server(ec.generate_private_key(ec.SECP256R1())) as port:
        r = scan_endpoint(f"127.0.0.1:{port}", allow_private=True)
    assert r.tls_version == "TLSv1.3"
    assert r.key_exchange == "ECDHE (TLS 1.3)"
    assert r.cert["key_type"] == "ECDSA" and r.cert["key_detail"] == "secp256r1"
    assert r.cert["self_signed"] is True and r.cert["names"] == ["crypt-test.local"]
    assert 28 <= r.cert["days_left"] <= 30
    assert set(r.pq_groups) == {STD_GROUP, DRAFT_GROUP}
    assert all(v in (True, False, None) for v in r.pq_groups.values())
    assert "CERT-001" in rule_ids(r.findings)
    assert 0 <= r.score <= 100


def test_scan_tls12_only_server_with_rsa_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with local_tls_server(key, max_version=ssl.TLSVersion.TLSv1_2) as port:
        r = scan_endpoint(f"127.0.0.1:{port}", allow_private=True)
    assert r.tls_version == "TLSv1.2"
    assert r.cert["key_type"] == "RSA" and r.cert["key_bits"] == 2048
    assert r.pq_groups == {STD_GROUP: False, DRAFT_GROUP: False}  # TLS 1.2 cannot do ML-KEM
    assert {"KEX-001", "VER-002", "CERT-001"} <= rule_ids(r.findings)
    assert r.label in {"MEDIUM", "HIGH"}


def test_scan_reports_closed_port_and_non_tls_service():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    try:
        scan_endpoint(f"127.0.0.1:{port}", timeout=2, allow_private=True)
    except EndpointError as err:
        assert err.status == 502 and "refused" in str(err)
    else:
        raise AssertionError("closed port did not raise")

    with fake_tls_server(b"HTTP/1.1 400 Bad Request\r\n\r\n") as port:
        try:
            scan_endpoint(f"127.0.0.1:{port}", timeout=2, allow_private=True)
        except EndpointError as err:
            assert err.status == 502
        else:
            raise AssertionError("plain-text service did not raise")


def test_module_exposes_allowed_ports():
    assert 443 in tls_scan.ALLOWED_PORTS and 22 not in tls_scan.ALLOWED_PORTS


def test_probe_sees_real_openssl_hello_retry_request():
    """Validates the hand-built ClientHello against a real TLS stack.

    OpenSSL supports X25519 (0x001D), so offering only that group with an empty
    key share must make it answer with a HelloRetryRequest. A group it has never
    heard of must be refused.
    """
    with local_tls_server(ec.generate_private_key(ec.SECP256R1())) as port:
        assert probe_group("127.0.0.1", port, None, 0x001D, 3) is True
        assert probe_group("127.0.0.1", port, None, 0x0A0A, 3) is False
