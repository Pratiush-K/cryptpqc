"""Deliberately vulnerable demo: protects files with classical public-key crypto."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

vault_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def encrypt_file_key(file_key: bytes) -> bytes:
    return vault_key.public_key().encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def make_session_secret(peer_public_key):
    session_key = ec.generate_private_key(ec.SECP256R1())
    return session_key.exchange(ec.ECDH(), peer_public_key)