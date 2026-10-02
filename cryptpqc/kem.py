"""Hybrid key encapsulation: X25519 (classical) + ML-KEM-768 (post-quantum)."""
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from kyber_py.ml_kem import ML_KEM_768


@dataclass
class PublicKey:
    x25519: bytes
    mlkem: bytes


@dataclass
class PrivateKey:
    x25519: bytes
    mlkem: bytes


def generate_keypair() -> tuple[PublicKey, PrivateKey]:
    """Create a hybrid public/private key pair."""
    x_priv = X25519PrivateKey.generate()
    x_pub_bytes = x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_priv_bytes = x_priv.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    mlkem_ek, mlkem_dk = ML_KEM_768.keygen()
    return PublicKey(x_pub_bytes, mlkem_ek), PrivateKey(x_priv_bytes, mlkem_dk)


def _combine(classical_secret: bytes, pq_secret: bytes, context: bytes) -> bytes:
    """Mix both shared secrets into one 32-byte AES key."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"crypt-hybrid-v1" + context,
    ).derive(classical_secret + pq_secret)


def encapsulate(public_key: PublicKey) -> tuple[bytes, bytes, bytes]:
    """Sender side. Returns (aes_key, ephemeral_x25519_pub, mlkem_ciphertext)."""
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    classical_secret = eph.exchange(
        X25519PublicKey.from_public_bytes(public_key.x25519)
    )
    pq_secret, pq_ct = ML_KEM_768.encaps(public_key.mlkem)
    key = _combine(classical_secret, pq_secret, eph_pub + pq_ct)
    return key, eph_pub, pq_ct


def decapsulate(private_key: PrivateKey, eph_pub: bytes, pq_ct: bytes) -> bytes:
    """Receiver side. Recovers the same 32-byte AES key."""
    x_priv = X25519PrivateKey.from_private_bytes(private_key.x25519)
    classical_secret = x_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    pq_secret = ML_KEM_768.decaps(private_key.mlkem, pq_ct)
    return _combine(classical_secret, pq_secret, eph_pub + pq_ct)
