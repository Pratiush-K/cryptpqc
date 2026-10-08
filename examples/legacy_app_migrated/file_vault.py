"""Migrated file-vault example."""

from cryptpqc import crypt_decrypt, crypt_encrypt, crypt_keygen


public_key, private_key = crypt_keygen()


def encrypt_file_key(file_key: bytes):
    return crypt_encrypt(public_key, file_key)


def decrypt_file_key(envelope) -> bytes:
    return crypt_decrypt(private_key, envelope)