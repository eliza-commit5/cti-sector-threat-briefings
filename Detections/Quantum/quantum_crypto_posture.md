# Quantum Cryptographic Posture & HNDL Guidance

> **TLP:CLEAR.** Governance and monitoring guidance for the cryptographic ("Harvest Now, Decrypt Later") side of the quantum threat. Pair with the detection queries in this folder.

Author / maintained by Eliza / eliza-commit5

## Why this exists

The quantum threat to the enterprise has two faces. One is **active intrusion / IP theft** against quantum R&D — covered by the APT41 pack and the data-exfil queries here. The other is **Harvest Now, Decrypt Later (HNDL)**: an adversary records encrypted traffic and stored ciphertext *today* and decrypts it later, once a cryptographically relevant quantum computer exists. HNDL is not a future risk for data with a long confidentiality lifetime — the exposure is created the moment that data crosses the wire under quantum-vulnerable encryption. This document is the framing and the remediation backlog that the `B2` exposure queries feed into.

## What quantum actually breaks

| Category | Examples | Quantum impact | Action |
|---|---|---|---|
| Asymmetric (public-key) | RSA, Diffie-Hellman (DH/ECDH), ECDSA, EdDSA, DSA, ElGamal | **Broken** by Shor's algorithm — key exchange and digital signatures fall | Migrate to PQC |
| Symmetric ciphers | AES-128, 3DES | **Weakened** by Grover (≈ halves effective strength); 3DES already deprecated | Use **AES-256** |
| Hashes | SHA-1, SHA-256, SHA-3 | SHA-256/3 effectively reduced but remain acceptable at current sizes; SHA-1 already broken | Use SHA-384/512 for long-life |

The headline: **all the public-key crypto protecting key exchange and authentication today is the part that fails.** Symmetric crypto survives at larger key sizes.

## The standards & the clock

NIST finalized the first post-quantum standards in 2024:

- **FIPS 203 — ML-KEM** (CRYSTALS-Kyber): key encapsulation / key exchange.
- **FIPS 204 — ML-DSA** (CRYSTALS-Dilithium): primary digital signatures.
- **FIPS 205 — SLH-DSA** (SPHINCS+): stateless hash-based signatures (conservative backup).
- **FN-DSA** (Falcon) is expected as a further signature standard.

Transition timelines to plan against (verify the current text of each before committing dates):

- **NIST IR 8547** (transition guidance) signals **deprecating** quantum-vulnerable public-key algorithms around **2030** and **disallowing** them by **2035**.
- **NSA CNSA 2.0** requires PQC for National Security Systems on a staged schedule, with new acquisitions expected to support CNSA 2.0 from **2027** and broad exclusive use by the early 2030s.

> Treat 2030–2035 as the window in which quantum-vulnerable crypto becomes non-compliant. Data that must stay secret beyond then is *already* exposed under HNDL.

## Build a Cryptographic Bill of Materials (CBOM)

You cannot migrate what you cannot see. A **CBOM** inventories every place cryptography is used — protocols, libraries, certificates, keys, HSMs, hardcoded primitives. CycloneDX supports CBOM as a format. Inventory sources to feed it:

- **Network**: TLS/SSH cipher & key-exchange inventory (the `B2` queries in `quantum_data_exfil_*`), passive sensor (Zeek `ssl.log`/`ssh.log`), active scanning (e.g., `sslscan`, `testssl.sh`, `nmap --script ssl-enum-ciphers`).
- **Certificates**: key algorithm and size across your PKI / cert manager (flag RSA-2048, ECDSA P-256, etc.).
- **Code & dependencies**: SAST / dependency scanning for calls to RSA/EC/DH primitives and crypto libraries.
- **Keys & secrets**: HSM, KMS, and key-vault inventories by algorithm.

## Prioritize by confidentiality lifetime

Migrate in order of **how long the data must stay secret**, because that is exactly what determines HNDL exposure:

1. Data with multi-decade secrecy needs (state secrets, source code, identity/biometric, health, long-lived keys/root CAs).
2. Long-lived authentication material (root/intermediate CAs, code-signing keys, firmware signing).
3. Everything else, in step with vendor PQC support.

Favor **hybrid** key exchange (classical + PQC, e.g. `X25519MLKEM768`) during transition so you are no worse off if either component is later weakened.

## How the queries in this folder map here

| Query | Role |
|---|---|
| `quantum_data_exfil_*` **B1** | Detects the HNDL *harvest* (bulk encrypted egress) |
| `quantum_data_exfil_*` **B2** | Inventories HNDL *exposure* (quantum-vulnerable TLS/SSH) → feeds the CBOM / migration backlog |
| `quantum_data_exfil_*` **A1–A3** | R&D IP theft / insider exfil (the espionage side) |
| `apt41_*` | The intrusion actor most associated with high-tech / R&D IP theft |

## Sources

- NIST — FIPS [203](https://csrc.nist.gov/pubs/fips/203/final), [204](https://csrc.nist.gov/pubs/fips/204/final), [205](https://csrc.nist.gov/pubs/fips/205/final)
- NIST — IR 8547, *Transition to Post-Quantum Cryptography Standards*
- NSA — Commercial National Security Algorithm Suite (CNSA) 2.0
- CISA / NSA / NIST — *Quantum-Readiness: Migration to Post-Quantum Cryptography*
- OWASP / CycloneDX — Cryptographic Bill of Materials (CBOM)
