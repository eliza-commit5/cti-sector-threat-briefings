# CyberAv3ngers (IRGC-CEC) — Detection Pack

> **TLP:CLEAR.** Detections compiled from primary reporting. Validate every indicator and rule against your own telemetry before operational use.

Iranian IRGC Cyber Electronic Command (IRGC-CEC) actor, also tracked as **Shahid Kaveh Group**. Targets internet-exposed OT/IoT in **water/wastewater, energy, and fuel management** — primarily via default-credential access to Unitronics PLC/HMI devices, and via the custom **IOCONTROL / OrpaCrab** Linux backdoor against fuel-management and IoT devices. U.S. Treasury sanctioned six associated IRGC-CEC officials in February 2024 (with a $10M Rewards for Justice bounty).

## Files

| File | Platform | What it covers |
|---|---|---|
| `cyberav3ngers_splunk.spl` | Splunk SPL (CIM) | Unitronics PCOM access, IOCONTROL C2 atomic indicators, MQTT-to-public-broker, DoH evasion |
| `cyberav3ngers_defender.kql` | Defender XDR / Sentinel | Same logic against `DeviceNetworkEvents` (best with Defender for IoT) |
| `iocontrol_orpacrab.yar` | YARA | Exact-hash rule + tampered-UPX heuristic for the IOCONTROL ELF |

## Indicators of compromise

**Validity warning:** the atomic network/file indicators below are from the 2023–2024 IOCONTROL campaign and are **very likely dead or sinkholed today**. Treat them as **retro-hunt** material. The durable detections are the *behavioral* ones (Unitronics port exposure, MQTT-to-public-broker, DoH from OT hosts).

| Type | Indicator | Notes |
|---|---|---|
| SHA-256 | `1b39f9b2b96a6586c4a11ab2fdbff8fdf16ba5a0ac7603149023d73f33b84498` | IOCONTROL sample (ARM-32 BE ELF, UPX-packed) |
| C2 domain | `tylarion867mino[.]com` | Registered 2023-11-23 |
| C2 FQDN | `uuokhhfsdlk[.]tylarion867mino[.]com` | From decrypted config |
| C2 IP | `159.100.6.69` | Resolution at time of Team82 report |
| Seed GUID | `855958ce-6483-4953-8c18-3f9625d88c27` | Per-victim; binary-patched; AES key seed |
| TCP port | `20256` (PCOM) | Unitronics PLC/HMI management |
| Protocol | MQTT (`1883`/`8883`) | C2 channel |
| Technique | DNS-over-HTTPS via Cloudflare `1.1.1.1` | C2 resolution / DNS evasion |

> The malware's config (including the C2 domain and GUID) is **AES-256-CBC encrypted inside the packed binary**, so these strings will **not** appear in plaintext on disk — which is exactly why the C2 indicators are implemented as network detections, not YARA strings. See the header comments in `iocontrol_orpacrab.yar`.

## MITRE ATT&CK (ICS / Enterprise)

- **Initial Access** — Internet-exposed device, default credentials (T1078 / ICS T0822)
- **Command and Control** — Application-layer protocol over MQTT (T1071); DoH for resolution (T1572 / T1071.004)
- **Persistence** — Backdoor auto-executes on device restart (ICS T0889 / T1547-style)
- **Impact (ICS)** — HMI defacement, loss of view/control, denial of service to fuel/water systems (T0815, T0826, T0813)

## Deployment notes

- **OT visibility is the gating factor.** PLCs and fuel terminals don't run endpoint agents, so you need a network sensor (Zeek/NDR, Dragos, Nozomi, or Microsoft Defender for IoT) feeding Splunk/Sentinel for these to fire.
- **Tune the allow-lists / asset scoping** in each query (internal CIDRs, approved MQTT brokers, OT host tags) before enabling — several queries are deliberately broad and will be noisy without scoping.
- **YARA heuristic is triage-grade**, not for endpoint blocking — the tampered-UPX marker is generic and will false-positive. The exact-hash rule is safe to deploy as-is.

## Sources

- CISA [AA23-335A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a) — IRGC-affiliated actors exploiting Unitronics PLCs in WWS/critical infrastructure
- Claroty Team82 — [Inside a New OT/IoT Cyberweapon: IOCONTROL](https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol)
- Claroty Team82 — [From Exploits to Forensics: Unraveling the Unitronics Attack](https://claroty.com/team82/research/from-exploits-to-forensics-unraveling-the-unitronics-attack)
