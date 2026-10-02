from cryptpqc.bench import HYBRID_NAME, MLKEM_NAME, RSA_NAME, X25519_NAME, run_benchmarks


def test_sizes_match_the_standards():
    results = run_benchmarks(iterations=2)["results"]
    assert results[MLKEM_NAME]["public_key_bytes"] == 1184
    assert results[MLKEM_NAME]["ciphertext_bytes"] == 1088
    assert results[X25519_NAME]["public_key_bytes"] == 32
    assert results[X25519_NAME]["ciphertext_bytes"] == 32
    assert results[RSA_NAME]["ciphertext_bytes"] == 256
    assert results[HYBRID_NAME]["public_key_bytes"] == 32 + 1184
    assert results[HYBRID_NAME]["ciphertext_bytes"] == 32 + 1088


def test_timings_are_positive_and_flags_are_right():
    results = run_benchmarks(iterations=2)["results"]
    for scheme in results.values():
        assert scheme["keygen_ms"] > 0
        assert scheme["encaps_ms"] > 0
        assert scheme["decaps_ms"] > 0
    assert results[RSA_NAME]["quantum_safe"] is False
    assert results[X25519_NAME]["quantum_safe"] is False
    assert results[MLKEM_NAME]["quantum_safe"] is True
    assert results[HYBRID_NAME]["quantum_safe"] is True