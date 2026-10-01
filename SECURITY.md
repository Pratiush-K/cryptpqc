# Security

Crypt is a hackathon prototype and has not been independently audited.

- The default ML-KEM backend (`kyber-py`) is educational and not constant-time.
  Do not use it to protect real secrets.
- Production deployments should use an audited library such as liboqs.
- Report vulnerabilities by opening a private security advisory on this repository.
