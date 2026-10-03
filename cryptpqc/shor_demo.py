"""Toy RSA plus a classical simulation of Shor's algorithm (for the web demo).

The quantum step of Shor's algorithm (finding the period of a^x mod N) is
replaced by brute force, so this only works on tiny keys. The surrounding
maths (pick a, find the order r, take gcds, rebuild the private key) is the
same as in the real attack.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from math import gcd


def _primes_with_bits(bits: int) -> list[int]:
	lo, hi = 1 << (bits - 1), (1 << bits) - 1
	sieve = bytearray([1]) * (hi + 1)
	sieve[0:2] = b"\x00\x00"
	for i in range(2, int(hi**0.5) + 1):
		if sieve[i]:
			sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
	return [n for n in range(lo, hi + 1) if sieve[n]]


@dataclass(frozen=True)
class ToyRSA:
	p: int
	q: int
	n: int
	e: int
	d: int


def make_toy_rsa(modulus_bits: int = 20, seed: int = 0) -> ToyRSA:
	"""Build a small RSA key whose modulus has about `modulus_bits` bits."""
	if not 12 <= modulus_bits <= 24:
		raise ValueError("modulus_bits must be between 12 and 24")
	rng = random.Random(seed)
	primes = _primes_with_bits(modulus_bits // 2)
	while True:
		p, q = rng.sample(primes, 2)
		phi = (p - 1) * (q - 1)
		for e in (65537, 257, 17, 5, 3):
			if gcd(e, phi) == 1:
				return ToyRSA(p, q, p * q, e, pow(e, -1, phi))


def rsa_encrypt_text(key: ToyRSA, text: str) -> list[int]:
	"""Textbook RSA, one byte at a time. Insecure on purpose."""
	return [pow(b, key.e, key.n) for b in text.encode("utf-8")]


def rsa_decrypt_text(n: int, d: int, blocks: list[int]) -> str:
	return bytes(pow(c, d, n) for c in blocks).decode("utf-8", errors="replace")


def find_order(a: int, n: int) -> int:
	"""Smallest r > 0 with a^r = 1 (mod n). Brute force stands in for the quantum step."""
	x, r = a % n, 1
	while x != 1:
		x = x * a % n
		r += 1
	return r


@dataclass
class Attempt:
	a: int
	order: int | None
	outcome: str


@dataclass
class ShorResult:
	n: int
	p: int | None = None
	q: int | None = None
	attempts: list[Attempt] = field(default_factory=list)
	seconds: float = 0.0

	@property
	def success(self) -> bool:
		return self.p is not None


def shor_factor(n: int, seed: int = 0, max_attempts: int = 60) -> ShorResult:
	"""Factor an odd composite n using Shor's classical post-processing."""
	start = time.perf_counter()
	res = ShorResult(n=n)
	rng = random.Random(seed)
	for _ in range(max_attempts):
		a = rng.randrange(2, n - 1)
		g = gcd(a, n)
		if g > 1:
			res.attempts.append(Attempt(a, None, f"lucky guess: gcd(a, N) = {g}"))
			res.p, res.q = g, n // g
			break
		r = find_order(a, n)
		if r % 2:
			res.attempts.append(Attempt(a, r, "order is odd, retry"))
			continue
		y = pow(a, r // 2, n)
		if y == n - 1:
			res.attempts.append(Attempt(a, r, "a^(r/2) = -1 mod N, retry"))
			continue
		p = gcd(y - 1, n)
		if 1 < p < n:
			res.attempts.append(Attempt(a, r, f"success: gcd(a^(r/2) - 1, N) = {p}"))
			res.p, res.q = p, n // p
			break
		res.attempts.append(Attempt(a, r, "trivial factor, retry"))
	res.seconds = time.perf_counter() - start
	return res


def recover_private_exponent(p: int, q: int, e: int) -> int:
	return pow(e, -1, (p - 1) * (q - 1))
