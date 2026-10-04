"""Inspect a live TLS endpoint for quantum-vulnerable cryptography.

What it checks:
  * the TLS version and cipher the server negotiates;
  * the certificate's key type, size and signature hash;
  * whether the server supports hybrid post-quantum key exchange
    (X25519MLKEM768, or the older draft X25519Kyber768).

The post-quantum check does not depend on the local OpenSSL version. Crypt sends a
hand-built TLS 1.3 ClientHello that offers only the hybrid group and no key share.
A server that supports the group must answer with a HelloRetryRequest naming it;
a server that does not support it answers with an alert.

Because the server connects to addresses a user typed in, this module is
careful about SSRF: it resolves the name once, refuses anything that is not a
public internet address, connects to that exact address, and only allows
standard TLS ports.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from .scanner import risk_label

ALLOWED_PORTS = (443, 465, 563, 636, 853, 993, 995, 8443)
STD_GROUP = "X25519MLKEM768"
DRAFT_GROUP = "X25519Kyber768Draft00"
PQ_PROBES = {STD_GROUP: 0x11EC, DRAFT_GROUP: 0x6399}

# Fixed "random" value that marks a ServerHello as a HelloRetryRequest (RFC 8446).
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)
# Alerts a server sends when it cannot agree on the offered group or version.
REFUSAL_ALERTS = {40, 47, 70, 109}  # handshake_failure, illegal_parameter, protocol_version, missing_extension

_HOST_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")


class EndpointError(Exception):
    """A problem with the request or the remote server, safe to show to the user."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class EndpointFinding:
    rule_id: str
    severity: str  # HIGH / MEDIUM / LOW, same scale as the code scanner
    title: str
    why: str
    fix: str
    points: int


@dataclass
class EndpointReport:
    host: str
    port: int
    ip: str
    tls_version: str
    cipher: str
    cipher_bits: int
    key_exchange: str
    pq_groups: dict  # group name -> True (supported) / False (refused) / None (unclear)
    cert: dict | None
    findings: list
    strengths: list
    score: int
    label: str
    verdict: str
    verdict_kind: str  # ok / err / info, matches the web banners
    seconds: float


# ---------------------------------------------------------------- input and safety
def parse_target(text: str) -> tuple[str, int | None]:
    """Turn 'example.com', 'https://example.com/path' or 'example.com:8443' into (host, port)."""
    raw = (text or "").strip()
    if not raw or len(raw) > 300:
        raise EndpointError("Enter a website address, like example.com.")
    if "://" not in raw:
        raw = "//" + raw
    try:
        parts = urlsplit(raw)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise EndpointError("That doesn't look like a valid address.") from None
    if not host:
        raise EndpointError("Enter a website address, like example.com.")
    host = host.rstrip(".").lower()
    if not _is_ip(host):
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise EndpointError("That doesn't look like a valid address.") from None
        if len(host) > 253 or not _HOST_RE.fullmatch(host):
            raise EndpointError("That doesn't look like a valid address.")
    return host, port


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve(host: str, port: int, allow_private: bool = False) -> str:
    """Resolve once and return the address to connect to. Refuses non-public addresses."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise EndpointError(f"Could not find {host}. Check the spelling.") from None
    addrs: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in addrs:
            addrs.append(ip)
    if not addrs:
        raise EndpointError(f"Could not find {host}. Check the spelling.")
    if not allow_private and not all(_is_public(a) for a in addrs):
        raise EndpointError(
            "Crypt only scans public internet hosts. Private, local and reserved addresses are blocked."
        )
    addrs.sort(key=lambda a: ":" in a)  # prefer IPv4
    return addrs[0]


# ---------------------------------------------------------------- the normal handshake
def _handshake(ip: str, port: int, sni: str | None, timeout: float) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we inspect the server, we don't trust it
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # lets us see legacy servers instead of failing
    except (ssl.SSLError, ValueError):
        pass
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except TimeoutError:
        raise EndpointError(f"Timed out connecting to port {port}.", 502) from None
    except ConnectionRefusedError:
        raise EndpointError(f"Connection refused on port {port}. Nothing is listening there.", 502) from None
    except OSError as err:
        raise EndpointError(f"Could not connect: {err.strerror or err}.", 502) from None
    try:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            return {
                "der": tls.getpeercert(binary_form=True),
                "version": tls.version() or "unknown",
                "cipher": tls.cipher() or ("unknown", "", 0),
            }
    except ssl.SSLError as err:
        raise EndpointError(
            f"The server did not complete a TLS handshake ({err.reason or err}). Is this a TLS service?", 502
        ) from None
    except TimeoutError:
        raise EndpointError("The TLS handshake timed out.", 502) from None
    except OSError as err:
        raise EndpointError(f"The connection dropped during the handshake ({err.strerror or err}).", 502) from None
    finally:
        sock.close()


def key_exchange_family(version: str, cipher_name: str) -> str:
    """Describe the classical key exchange behind a negotiated cipher."""
    if version == "TLSv1.3":
        return "ECDHE (TLS 1.3)"
    if cipher_name.startswith("ECDHE"):
        return "ECDHE"
    if cipher_name.startswith(("DHE", "EDH")):
        return "DHE"
    if cipher_name.startswith("ECDH"):
        return "Static ECDH"
    return "RSA key transport"


# ---------------------------------------------------------------- certificate
def describe_cert(der: bytes) -> dict | None:
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return None
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        key_type, bits, detail = "RSA", pk.key_size, f"{pk.key_size}-bit"
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        key_type, bits, detail = "ECDSA", pk.curve.key_size, pk.curve.name
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        key_type, bits, detail = "Ed25519", 256, "Curve25519"
    elif isinstance(pk, ed448.Ed448PublicKey):
        key_type, bits, detail = "Ed448", 448, "Curve448"
    elif isinstance(pk, dsa.DSAPublicKey):
        key_type, bits, detail = "DSA", pk.key_size, f"{pk.key_size}-bit"
    else:
        key_type, bits, detail = type(pk).__name__, 0, "unknown"
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "built-in"
    except Exception:  # unsupported signature algorithm OID
        sig_hash = "unknown"

    def utc(attr: str) -> datetime:
        value = getattr(cert, attr + "_utc", None)
        return value if value is not None else getattr(cert, attr).replace(tzinfo=timezone.utc)

    def name_of(name: x509.Name) -> str:
        for oid in (x509.NameOID.COMMON_NAME, x509.NameOID.ORGANIZATION_NAME):
            values = name.get_attributes_for_oid(oid)
            if values:
                return str(values[0].value)
        return "unknown"

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)[:8]
    except x509.ExtensionNotFound:
        names = []
    expires = utc("not_valid_after")
    return {
        "subject": name_of(cert.subject),
        "issuer": name_of(cert.issuer),
        "self_signed": cert.subject == cert.issuer,
        "key_type": key_type,
        "key_bits": bits,
        "key_detail": detail,
        "sig_hash": sig_hash,
        "not_before": utc("not_valid_before").date().isoformat(),
        "not_after": expires.date().isoformat(),
        "days_left": (expires - datetime.now(timezone.utc)).days,
        "names": names,
    }


# ---------------------------------------------------------------- post-quantum probe
def build_client_hello(sni: str | None, group_id: int) -> bytes:
    """A TLS 1.3 ClientHello that offers one key-exchange group and sends no key share."""

    def u16(n: int) -> bytes:
        return struct.pack("!H", n)

    def ext(ext_type: int, data: bytes) -> bytes:
        return u16(ext_type) + u16(len(data)) + data

    exts = b""
    if sni:
        name = sni.encode("ascii")
        exts += ext(0x0000, u16(len(name) + 3) + b"\x00" + u16(len(name)) + name)
    exts += ext(0x002B, b"\x02\x03\x04")  # supported_versions: TLS 1.3 only
    exts += ext(0x000A, u16(2) + u16(group_id))  # supported_groups
    sigalgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807]
    exts += ext(0x000D, u16(2 * len(sigalgs)) + b"".join(u16(s) for s in sigalgs))
    exts += ext(0x0033, u16(0))  # key_share: empty list asks the server to pick a group
    suites = [0x1301, 0x1302, 0x1303]
    body = (
        b"\x03\x03"
        + os.urandom(32)
        + b"\x20" + os.urandom(32)  # legacy session id, for middlebox compatibility
        + u16(2 * len(suites)) + b"".join(u16(s) for s in suites)
        + b"\x01\x00"
        + u16(len(exts)) + exts
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + u16(len(handshake)) + handshake


def parse_server_reply(data: bytes) -> tuple[str, int | None]:
    """Classify the first TLS record from the server.

    Returns (kind, value): ('alert', code), ('server_hello', group),
    ('hello_retry', group), ('tls12', None) or ('unknown', None).
    """
    if len(data) < 6:
        return "unknown", None
    if data[0] == 0x15:
        return "alert", data[6] if len(data) > 6 else None
    if data[0] != 0x16 or len(data) < 9 or data[5] != 0x02:
        return "unknown", None
    try:
        pos = 9 + 2  # record header, handshake header, legacy_version
        random = data[pos : pos + 32]
        pos += 32
        pos += 1 + data[pos]  # session id
        pos += 3  # cipher suite and compression method
        ext_len = struct.unpack_from("!H", data, pos)[0]
        pos += 2
        end = pos + ext_len
        selected, tls13 = None, False
        while pos + 4 <= end:
            ext_type, length = struct.unpack_from("!HH", data, pos)
            pos += 4
            payload = data[pos : pos + length]
            pos += length
            if ext_type == 0x002B and payload == b"\x03\x04":
                tls13 = True
            elif ext_type == 0x0033 and len(payload) >= 2:
                selected = struct.unpack_from("!H", payload)[0]
    except (struct.error, IndexError):
        return "unknown", None
    if not tls13:
        return "tls12", None
    return ("hello_retry" if random == HRR_RANDOM else "server_hello"), selected


def _read_record(sock: socket.socket) -> bytes:
    buf = b""
    while len(buf) < 5:
        chunk = sock.recv(4096)
        if not chunk:
            return buf
        buf += chunk
    need = 5 + min(struct.unpack_from("!H", buf, 3)[0], 18432)
    while len(buf) < need:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def probe_group(ip: str, port: int, sni: str | None, group_id: int, timeout: float) -> bool | None:
    """True if the server accepts the group, False if it refuses it, None if unclear."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(build_client_hello(sni, group_id))
            reply = _read_record(sock)
    except OSError:
        return None
    kind, value = parse_server_reply(reply)
    if kind in ("hello_retry", "server_hello"):
        return value == group_id
    if kind == "tls12":
        return False
    if kind == "alert" and value in REFUSAL_ALERTS:
        return False
    return None


# ---------------------------------------------------------------- assessment
def assess(
    tls_version: str, key_exchange: str, pq_groups: dict, cert: dict | None
) -> tuple[list[EndpointFinding], list[str], str, str]:
    """Turn raw observations into findings, strengths and a one-line verdict. No network."""
    findings: list[EndpointFinding] = []
    strengths: list[str] = []
    std, draft = pq_groups.get(STD_GROUP), pq_groups.get(DRAFT_GROUP)

    if std is True:
        strengths.append(f"Hybrid post-quantum key exchange ({STD_GROUP}) is supported.")
        verdict_kind = "ok"
        verdict = (
            f"Post-quantum ready: this server supports hybrid key exchange ({STD_GROUP}). "
            "Traffic from clients that offer it is protected against harvest-now-decrypt-later."
        )
    elif draft is True:
        verdict_kind = "info"
        verdict = (
            "Partly protected: only the older draft Kyber hybrid is supported. "
            f"Current browsers use {STD_GROUP}, so most traffic is still classical."
        )
        findings.append(EndpointFinding(
            "KEX-002", "MEDIUM", "Only the draft Kyber hybrid is supported",
            f"{DRAFT_GROUP} was an early experiment. Browsers have moved to {STD_GROUP} (ML-KEM, FIPS 203).",
            f"Enable {STD_GROUP} on the server or CDN.", 25,
        ))
    elif std is False:
        verdict_kind = "err"
        verdict = (
            "Exposed to harvest-now-decrypt-later: this server only offers classical key exchange, "
            "so traffic recorded today could be decrypted once a large quantum computer exists."
        )
        findings.append(EndpointFinding(
            "KEX-001", "HIGH", "Key exchange is classical only",
            "The server refused hybrid post-quantum key exchange. Attackers can record encrypted "
            "traffic now and break the key exchange later with Shor's algorithm.",
            f"Enable {STD_GROUP}: use OpenSSL 3.5 or newer, or put the site behind a CDN that supports it.", 60,
        ))
    else:
        verdict_kind = "info"
        verdict = "Could not confirm post-quantum support: the server did not answer the probe clearly. Try again."
        findings.append(EndpointFinding(
            "KEX-004", "MEDIUM", "Post-quantum key exchange could not be confirmed",
            "The server dropped the connection or sent an unexpected reply to the probe.",
            "Run the scan again. If it keeps happening, check for a firewall or load balancer in front.", 30,
        ))

    if key_exchange == "RSA key transport":
        findings.append(EndpointFinding(
            "KEX-003", "HIGH", "No forward secrecy (RSA key transport)",
            "Every recorded session can be decrypted by anyone who later obtains the server's RSA key, "
            "quantum computer or not.",
            "Disable RSA key-transport cipher suites. Prefer TLS 1.3.", 20,
        ))
    if tls_version in ("SSLv3", "TLSv1", "TLSv1.1"):
        findings.append(EndpointFinding(
            "VER-001", "HIGH", f"{tls_version} is obsolete",
            "This protocol version is deprecated and has known classical attacks.",
            "Require TLS 1.2 at minimum, and TLS 1.3 wherever you can.", 30,
        ))
    elif tls_version == "TLSv1.2" and std is not True and draft is not True:
        findings.append(EndpointFinding(
            "VER-002", "MEDIUM", "Negotiated TLS 1.2",
            "Post-quantum key exchange needs TLS 1.3, so TLS 1.2 sessions cannot use ML-KEM.",
            "Enable TLS 1.3.", 10,
        ))

    if cert:
        kt, bits = cert["key_type"], cert["key_bits"]
        if kt == "RSA" and bits < 2048:
            findings.append(EndpointFinding(
                "CERT-002", "HIGH", f"Certificate uses a weak RSA-{bits} key",
                "Keys this small are weak even against classical computers.",
                "Reissue the certificate with RSA-3072 or an ECDSA P-256 key, and plan for ML-DSA.", 20,
            ))
        else:
            findings.append(EndpointFinding(
                "CERT-001", "LOW", f"Certificate uses {kt} ({cert['key_detail']})",
                "Certificates prove identity. Forging one needs a quantum computer at the moment of the "
                "connection, so this is less urgent than key exchange. The web certificate ecosystem is "
                "still working on post-quantum signatures, so this is expected today.",
                "No action needed yet. Track ML-DSA (FIPS 204) support from your CA and keep certificate "
                "lifetimes short so you can switch quickly.", 10,
            ))
        if cert["sig_hash"] in ("sha1", "md5"):
            findings.append(EndpointFinding(
                "CERT-003", "HIGH", f"Certificate is signed with {cert['sig_hash'].upper()}",
                "This hash is broken by classical collision attacks. It is not a quantum issue.",
                "Reissue the certificate with a SHA-256 or stronger signature.", 15,
            ))
        if cert["days_left"] < 0:
            findings.append(EndpointFinding(
                "CERT-004", "MEDIUM", f"Certificate expired {-cert['days_left']} day(s) ago",
                "Not a quantum issue, but browsers will reject it.",
                "Renew the certificate.", 5,
            ))
    return findings, strengths, verdict, verdict_kind


# ---------------------------------------------------------------- entry point
def scan_endpoint(target: str, timeout: float = 5.0, allow_private: bool = False) -> EndpointReport:
    """Scan a host such as 'example.com' or 'example.com:8443' and return a report."""
    started = time.perf_counter()
    host, port = parse_target(target)
    port = port or 443
    if not allow_private and port not in ALLOWED_PORTS:
        allowed = ", ".join(str(p) for p in ALLOWED_PORTS)
        raise EndpointError(f"Port {port} is not allowed. Use one of: {allowed}.")
    ip = resolve(host, port, allow_private)
    sni = None if _is_ip(host) else host

    with ThreadPoolExecutor(max_workers=1 + len(PQ_PROBES)) as pool:
        main = pool.submit(_handshake, ip, port, sni, timeout)
        probes = {
            name: pool.submit(probe_group, ip, port, sni, gid, timeout)
            for name, gid in PQ_PROBES.items()
        }
        hs = main.result()
        pq_groups = {name: fut.result() for name, fut in probes.items()}

    version = hs["version"]
    cipher_name, _, cipher_bits = hs["cipher"]
    kex = key_exchange_family(version, cipher_name)
    cert = describe_cert(hs["der"]) if hs["der"] else None
    findings, strengths, verdict, verdict_kind = assess(version, kex, pq_groups, cert)
    score = min(100, sum(f.points for f in findings))
    return EndpointReport(
        host=host, port=port, ip=ip, tls_version=version, cipher=cipher_name,
        cipher_bits=cipher_bits or 0, key_exchange=kex, pq_groups=pq_groups, cert=cert,
        findings=findings, strengths=strengths, score=score, label=risk_label(score),
        verdict=verdict, verdict_kind=verdict_kind,
        seconds=round(time.perf_counter() - started, 2),
    )
