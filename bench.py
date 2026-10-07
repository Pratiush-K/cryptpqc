"""Benchmarks: classical key exchange vs post-quantum ML-KEM-768 vs Crypt's hybrid."""
from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kyber_py.ml_kem import ML_KEM_768

from .kem import decapsulate, encapsulate, generate_keypair

RSA_NAME = "RSA-2048 (OAEP)"
X25519_NAME = "X25519"
MLKEM_NAME = "ML-KEM-768"
HYBRID_NAME = "Crypt hybrid (X25519 + ML-KEM-768)"

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def _median_ms(fn, iterations: int) -> float:
    """Median wall-clock time of fn() in milliseconds, after one warm-up call."""
    fn()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - start) / 1e6)
    return statistics.median(samples)


def _bench_rsa(n_fast: int, n_slow: int) -> dict:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    secret = b"\x01" * 32
    ciphertext = pub.encrypt(secret, _OAEP)
    return {
        "keygen_ms": _median_ms(
            lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), n_slow
        ),
        "encaps_ms": _median_ms(lambda: pub.encrypt(secret, _OAEP), n_fast),
        "decaps_ms": _median_ms(lambda: key.decrypt(ciphertext, _OAEP), n_fast),
        "public_key_bytes": len(
            pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        ),
        "ciphertext_bytes": len(ciphertext),
        "quantum_safe": False,
    }


def _bench_x25519(n: int) -> dict:
    server = X25519PrivateKey.generate()
    server_pub = server.public_key()

    def encaps():
        ephemeral = X25519PrivateKey.generate()
        ephemeral.exchange(server_pub)
        return ephemeral.public_key()

    ephemeral_pub = encaps()
    return {
        "keygen_ms": _median_ms(X25519PrivateKey.generate, n),
        "encaps_ms": _median_ms(encaps, n),
        "decaps_ms": _median_ms(lambda: server.exchange(ephemeral_pub), n),
        "public_key_bytes": len(server_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "ciphertext_bytes": len(ephemeral_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "quantum_safe": False,
    }


def _bench_mlkem(n: int) -> dict:
    ek, dk = ML_KEM_768.keygen()
    _, ct = ML_KEM_768.encaps(ek)
    return {
        "keygen_ms": _median_ms(ML_KEM_768.keygen, n),
        "encaps_ms": _median_ms(lambda: ML_KEM_768.encaps(ek), n),
        "decaps_ms": _median_ms(lambda: ML_KEM_768.decaps(dk, ct), n),
        "public_key_bytes": len(ek),
        "ciphertext_bytes": len(ct),
        "quantum_safe": True,
    }


def _bench_hybrid(n: int) -> dict:
    pub, priv = generate_keypair()
    _, ephemeral_pub, pq_ct = encapsulate(pub)
    return {
        "keygen_ms": _median_ms(generate_keypair, n),
        "encaps_ms": _median_ms(lambda: encapsulate(pub), n),
        "decaps_ms": _median_ms(lambda: decapsulate(priv, ephemeral_pub, pq_ct), n),
        "public_key_bytes": len(pub.x25519) + len(pub.mlkem),
        "ciphertext_bytes": len(ephemeral_pub) + len(pq_ct),
        "quantum_safe": True,
    }


def run_benchmarks(iterations: int = 50) -> dict:
    """Measure key exchange for each scheme. RSA key generation is slow, so it runs fewer times."""
    n_slow = max(3, iterations // 5)
    return {
        "machine": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "cpu_count": os.cpu_count(),
        },
        "iterations": iterations,
        "note": (
            "Sizes are exact for each standard. Timings are medians on this machine. "
            "ML-KEM here uses kyber-py, a pure-Python educational library, so its times "
            "are pessimistic compared with optimized implementations such as liboqs."
        ),
        "results": {
            RSA_NAME: _bench_rsa(iterations, n_slow),
            X25519_NAME: _bench_x25519(iterations),
            MLKEM_NAME: _bench_mlkem(iterations),
            HYBRID_NAME: _bench_hybrid(iterations),
        },
    }


def save_json(data: dict, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def save_chart(data: dict, path: str | Path) -> None:
    """Draw a two-panel chart: bytes on the wire and operation times (log scale)."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names = list(data["results"])
    labels = [n.replace(" (X25519 + ML-KEM-768)", "\n(X25519 + ML-KEM)") for n in names]
    res = data["results"]
    x = range(len(names))
    width = 0.38

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8))

    ax1.bar([i - width / 2 for i in x], [res[n]["public_key_bytes"] for n in names],
            width, label="public key", color="#6d28d9")
    ax1.bar([i + width / 2 for i in x], [res[n]["ciphertext_bytes"] for n in names],
            width, label="ciphertext", color="#06b6d4")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(labels, fontsize=8)
    ax1.set_ylabel("bytes")
    ax1.set_title("Size on the wire")
    ax1.legend()

    w = 0.26
    for offset, (key, label, color) in enumerate(
        [("keygen_ms", "keygen", "#f59e0b"), ("encaps_ms", "encrypt side", "#6d28d9"),
         ("decaps_ms", "decrypt side", "#06b6d4")]
    ):
        ax2.bar([i + (offset - 1) * w for i in x], [res[n][key] for n in names],
                w, label=label, color=color)
    ax2.set_yscale("log")
    ax2.set_xticks(list(x))
    ax2.set_xticklabels(labels, fontsize=8)
    ax2.set_ylabel("milliseconds (log scale, median)")
    ax2.set_title("Time per operation")
    ax2.legend()

    fig.suptitle("Key exchange: classical vs post-quantum vs Crypt hybrid")
    fig.tight_layout()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)