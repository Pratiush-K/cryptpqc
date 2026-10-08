"""Deliberately vulnerable demo service. It exists to be scanned by `crypt scan`."""
import hashlib

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def issue_token(user_id: str) -> str:
    return jwt.encode({"sub": user_id}, signing_key, algorithm="RS256")


def hash_legacy_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()