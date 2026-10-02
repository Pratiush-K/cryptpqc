"""Public API: crypt_keygen, crypt_encrypt, crypt_decrypt."""
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .kem import PrivateKey, PublicKey, decapsulate, encapsulate, generate_keypair


@dataclass
class Envelope:
    """Everything the receiver needs to decrypt a message."""
    eph_pub: bytes
    pq_ct: bytes
    nonce: bytes
    ciphertext: bytes


def crypt_keygen() -> tuple[PublicKey, PrivateKey]:
    return generate_keypair()


def crypt_encrypt(
    public_key: PublicKey, plaintext: bytes, associated_data: bytes | None = None
) -> Envelope:
    key, eph_pub, pq_ct = encapsulate(public_key)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return Envelope(eph_pub, pq_ct, nonce, ciphertext)


def crypt_decrypt(
    private_key: PrivateKey, envelope: Envelope, associated_data: bytes | None = None
) -> bytes:
    key = decapsulate(private_key, envelope.eph_pub, envelope.pq_ct)
    return AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, associated_data)
