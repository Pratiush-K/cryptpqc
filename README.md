
# Crypt

**Scan your code for quantum-vulnerable cryptography, measure the risk, watch the attack, and move to post-quantum encryption.**

Today's public-key cryptography (RSA, elliptic curves) will be broken by a large enough quantum computer running Shor's algorithm. Attackers can already record encrypted traffic and decrypt it later ("harvest now, decrypt later"). Crypt helps you find where you are exposed and shows what to use instead.

Built for Q-Hack India 2026.

## What it does

| Tab / command     | What you get                                                                                                                                                                   |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Scan**    | Finds RSA, elliptic-curve and weak-hash usage in source files. Gives each finding a severity, a reason and a recommended fix, plus an overall risk score from 0 to 100.        |
| **Risk**    | Breaks the score down by algorithm, and includes a calculator for Mosca's inequality: you are exposed when*data shelf life + migration time > years until a quantum threat*. |
| **Attack**  | Breaks a toy RSA key with a simulation of Shor's algorithm and decrypts a secret message, step by step.                                                                        |
| **Defense** | Hybrid**X25519 + ML-KEM-768** encryption (AES-256-GCM), with a tamper test and benchmarks comparing RSA, X25519, ML-KEM and the hybrid.                                  |

The command-line tool and the website share the same Python backend (`cryptpqc/`).

## Quickstart

```bash
git clone https://github.com/Pratiush-K/crypt-pqc.git
cd crypt-pqc
pip install -r requirements-local.txt
python app.py
```

Open **http://localhost:5000**.

Requires Python 3.10 or newer.

### Command line

```bash
pip install -e .

crypt scan examples/legacy_app            # scan a file or folder
crypt scan examples/legacy_app --json     # machine-readable output
crypt bench --iterations 50               # benchmark the schemes
crypt bench --json out.json --chart out.png
```

### Use it as a library

```python
from cryptpqc import crypt_keygen, crypt_encrypt, crypt_decrypt

public_key, private_key = crypt_keygen()
envelope = crypt_encrypt(public_key, b"meet at noon")
print(crypt_decrypt(private_key, envelope))   # b'meet at noon'
```

## The website

`app.py` is a small Flask server. It serves the static front end in `web/` (plain HTML, CSS and JavaScript, no build step) and a JSON API that calls the same backend as the CLI.

| Endpoint                 | Purpose                                                  |
| ------------------------ | -------------------------------------------------------- |
| `POST /api/scan`       | Upload files or a`.zip`, get findings and a risk score |
| `POST /api/mosca`      | Mosca's inequality verdict                               |
| `POST /api/shor`       | Toy RSA key, Shor attack steps, recovered plaintext      |
| `POST /api/hybrid`     | Generate keys, encrypt, optionally tamper, decrypt       |
| `POST /api/bench`      | Run the benchmarks                                       |
| `GET /api/bench/saved` | Results saved in`docs/benchmarks.json`                 |

Uploaded files are analysed in a temporary folder and discarded. Zip extraction blocks path traversal and caps the expanded size.

If you open `web/index.html` with VS Code Live Server, keep `python app.py` running as well. The page then sends its API calls to `localhost:5000`.

## Deploying

The app runs on any host that can run a Python web app.

- **Vercel:** import the repo and deploy with the default settings. Vercel detects the Flask app in `app.py` and installs the packages in `pyproject.toml`. On Vercel the upload limit is 4 MB and benchmarks are capped at 10 iterations, because serverless functions have size and time limits.
- **Render or similar:** use `pip install -r requirements.txt` as the build command and `gunicorn app:app` as the start command (see `Procfile`).

## Project layout

```
cryptpqc/        scanner, risk, hybrid KEM, benchmarks, Shor demo, CLI
web/             index.html, style.css, app.js
app.py           Flask server and JSON API
examples/        legacy_app (vulnerable) and legacy_app_migrated
docs/            saved benchmark results and chart
notebooks/       Shor attack demo with Qiskit
tests/           pytest suite
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## How the hybrid encryption works

1. The sender does an X25519 key exchange and an ML-KEM-768 encapsulation against the recipient's public keys.
2. Both shared secrets are combined into one key, so an attacker has to break **both** algorithms to read the message.
3. The message is encrypted with AES-256-GCM, which also detects any modification of the ciphertext.

## Limitations

- The Shor demo is a classical simulation on tiny keys. The quantum period-finding step is replaced by brute force. Breaking real RSA-2048 needs a large fault-tolerant quantum computer that does not exist yet.
- ML-KEM uses [`kyber-py`](https://github.com/GiacomoPope/kyber-py), a pure-Python educational implementation. Its timings are much slower than optimised libraries such as liboqs, and it is not hardened against side-channel attacks. Do not use this project to protect real secrets without reviewing it first.
- The scanner uses pattern matching, so it can miss cryptography that is built dynamically and can flag harmless matches.

## License

MIT. See [LICENSE](LICENSE). To report a security issue, see [SECURITY.md](SECURITY.md).
