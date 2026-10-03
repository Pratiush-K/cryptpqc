import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location(
	"shor_demo", pathlib.Path(__file__).parents[1] / "cryptpqc" / "shor_demo.py"
)
sd = importlib.util.module_from_spec(spec)
sys.modules["shor_demo"] = sd
spec.loader.exec_module(sd)


def test_attack_recovers_plaintext():
	for bits in (12, 16, 20):
		key = sd.make_toy_rsa(bits, seed=3)
		blocks = sd.rsa_encrypt_text(key, "hello PQC")
		res = sd.shor_factor(key.n, seed=1)
		assert res.success and {res.p, res.q} == {key.p, key.q}
		d = sd.recover_private_exponent(res.p, res.q, key.e)
		assert sd.rsa_decrypt_text(key.n, d, blocks) == "hello PQC"
