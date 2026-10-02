import pytest
from cryptography.exceptions import InvalidTag

from cryptpqc import crypt_decrypt, crypt_encrypt, crypt_keygen


def test_round_trip():
    pub, priv = crypt_keygen()
    message = b"patient record #42"
    envelope = crypt_encrypt(pub, message)
    assert crypt_decrypt(priv, envelope) == message


def test_wrong_key_fails():
    pub, _ = crypt_keygen()
    _, other_priv = crypt_keygen()
    envelope = crypt_encrypt(pub, b"secret")
    with pytest.raises(InvalidTag):
        crypt_decrypt(other_priv, envelope)


def test_tampered_ciphertext_fails():
    pub, priv = crypt_keygen()
    envelope = crypt_encrypt(pub, b"secret")
    envelope.ciphertext = bytes([envelope.ciphertext[0] ^ 1]) + envelope.ciphertext[1:]
    with pytest.raises(InvalidTag):
        crypt_decrypt(priv, envelope)
