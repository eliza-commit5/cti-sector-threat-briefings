[README.md](https://github.com/user-attachments/files/28851501/README.md)
# Quantum Vertical — Detection & Posture Pack

> **TLP:CLEAR.** Compiled from primary reporting and NIST/NSA guidance. Validate every indicator, rule, and date against the original sources before operational use.

Maintained by Eliza / eliza-commit5

The quantum vertical is unlike the other actor-centric packs in this repo: it is **not one named adversary with a malware toolset**. It is **two distinct threat models**, and this pack covers both, plus the cryptographic-posture work that is unique to quantum.

## The two threat models

| | Threat model | What it looks like | Coverage here |
|---|---|---|---|
| **1** | **IP theft / espionage** against quantum R&D | Intrusion, persistence, IP exfiltration (APT41-style) | `apt41_*`, plus `quantum_data_exfil_*` A1–A3 |
| **2** | **Harvest Now, Decrypt Later (HNDL)** | Bulk encrypted collection now → quantum decryption later; exposure from quantum-vulnerable crypto | `quantum_data_exfil_*` B1–B2, `quantum_crypto_posture.md` |

> **There is no "quantum malware."** Defending this vertical means (a) catching the *intrusion actor* who steals quantum IP, (b) catching *bulk data exfiltration / harvest*, and (c) *inventorying and migrating* quantum-vulnerable cryptography. This pack does all three.

## Files

| File | Platform | Threat model | What it covers |
|---|---|---|---|
| `apt41_splunk.spl` | Splunk SPL | 1 | DLL side-loading, masqueraded process, certutil staging, cloud C2, web shell, hashes |
| `apt41_defender.kql` | Defender XDR / Sentinel | 1 | Same logic across device tables |
| `apt41_malware.yar` | YARA | 1 | DUSTTRAP/DUSTPAN loader heuristic + hash rule (honest scope note inside) |
| `quantum_data_exfil_splunk.spl` | Splunk SPL | 1 + 2 | Mass file access, archive staging, cloud/USB exfil, bulk encrypted egress, crypto-exposure inventory |
| `quantum_data_exfil_defender.kql` | Defender XDR / Sentinel | 1 + 2 | Same logic across device/network tables |
| `quantum_crypto_posture.md` | Guidance | 2 | Quantum-vulnerable algorithms, NIST PQC standards & timeline, CBOM, prioritization |

## Why APT41 for threat model 1

The briefing's quantum espionage threat is **APT41-style IP theft** (China-nexus economic espionage against high-tech / R&D), not a quantum-specific group. APT41 is the most appropriate concrete actor: it targets high-tech and research sectors, compromised a government-affiliated **research institute** (ShadowPad + Cobalt Strike, per Talos), and runs a deep toolset (DUSTTRAP, DUSTPAN, KEYPLUG, ShadowPad). Other China-nexus IP-theft actors (APT31, APT40, Mustang Panda) share much of this tradecraft, so the **behavioral** queries here generalize beyond APT41.

## Key behaviors & artifacts (APT41)

| Behavior | Tell | Fidelity |
|---|---|---|
| DLL side-loading | signed EXE loading a DLL from ProgramData/Temp/Public | High |
| Masquerade | `w3wp.exe` outside `\System32\inetsrv\`; `conn.exe` | High |
| Staging/download | `certutil` urlcache/decode; free hosting (workers.dev, trycloudflare, infinityfree) | Medium |
| Cloud C2 | TOUGHPROGRESS abuses **Google Calendar** for C2 | Medium (hunt) |
| Loaders | DUSTTRAP (AES-128-CFB, MachineGUID-keyed, `.dll.mui`), DUSTPAN (ChaCha20 BEACON), KEYPLUG (Win+Linux, multi-protocol) | — |

> DUSTTRAP keys decryption to each victim's `MachineGuid`, so payloads are per-host — lead with behavior, not file hashes. The YARA leg is secondary here (packed/in-memory/side-loaded).

## Deployment notes

- **Threat model 1** needs endpoint telemetry (Sysmon/EDR), web-server logs, and proxy/DNS. The side-loading and masquerade queries are the highest fidelity.
- **Threat model 2** needs network flow + TLS/SSH metadata (Zeek/NetFlow/firewall) and file-access auditing. `B2` is an *exposure inventory*, not an alert — its output is your crypto-migration backlog.
- **Tune every threshold** (file-count, byte-volume, egress allow-lists) to your baseline; these surface candidates to triage, not turnkey alerts.
- Populate the hash placeholders (`apt41_hashes.csv`, the KQL `apt41_hashes` list, the YARA hash rule) from Mandiant/Talos/Tinexta appendices.

## Sources

- Google / Mandiant — [APT41 Has Arisen From the DUST](https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust)
- Cisco Talos — [APT41 compromised a Taiwanese research institute with ShadowPad and Cobalt Strike](https://blog.talosintelligence.com/chinese-hacking-group-apt41-compromised-taiwanese-government-affiliated-research-institute-with-shadowpad-and-cobaltstrike-2/)
- Tinexta Cyber — KEYPLUG analysis; MITRE ATT&CK [G0096 (APT41)](https://attack.mitre.org/groups/G0096/)
- NIST FIPS 203/204/205, NIST IR 8547, NSA CNSA 2.0, CISA *Quantum-Readiness* (see `quantum_crypto_posture.md`)
