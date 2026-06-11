[README.md](https://github.com/user-attachments/files/28849876/README.md)
# Volt Typhoon (VOLTZITE) — Detection Pack

> **TLP:CLEAR.** Detections compiled from primary reporting. Validate every indicator and rule against your own telemetry before operational use.

Maintained by Eliza / eliza-commit5

PRC state-sponsored actor (also **VOLTZITE, Vanguard Panda, BRONZE SILHOUETTE, Insidious Taurus**), active since ~2021. Unlike espionage-focused groups, Volt Typhoon **pre-positions** in US critical infrastructure — communications, energy, water, transportation — for potential **disruptive/destructive attacks during a future crisis or conflict** (notably a Taiwan scenario). CISA assesses some accesses have been maintained for **5+ years**.

## The defining characteristic: Living off the Land

Volt Typhoon uses **built-in Windows tools and valid credentials**, not custom malware, to blend into normal administration and evade EDR. It proxies C2 through **compromised SOHO/edge routers** (the KV-botnet, disrupted by the FBI/DOJ in early 2024). This shapes everything about detection:

> **There is little to YARA.** The real coverage for this actor is **behavioral** — the SPL and KQL queries here. The YARA file is deliberately thin and honest about that. Conversely, **logging coverage is decisive**: command-line process auditing, PowerShell logging, and registry auditing must be on, or these queries see nothing.

## Files

| File | Platform | What it covers |
|---|---|---|
| `volt_typhoon_splunk.spl` | Splunk SPL | portproxy, ntdsutil/NTDS.dit, comsvcs LSASS dump, PowerShell logon enum, discovery burst, hash retro-hunt |
| `volt_typhoon_defender.kql` | Defender XDR / Sentinel | Same logic + sign-in anomaly correlation (queries 1-2 adapted from Microsoft) |
| `volt_typhoon_tooling.yar` | YARA | Custom-FRP hash rule + dual-use FRP hunt rule (weakest leg — see note) |

## Key behaviors & artifacts

| Behavior | Artifact / tell | Fidelity |
|---|---|---|
| Internal proxy (LOTL) | `netsh interface portproxy add v4tov4 ...`; registry `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp\` | High (rare in normal ops) |
| NTDS.dit theft | `ntdsutil ... create full` / `ac i ntds` / `ifm`; ESENT Application events 216, 325, 326, 327 | High |
| Credential dump | `rundll32 comsvcs.dll, MiniDump` against LSASS | High |
| Account recon | PowerShell querying Security log for 4624 logons | Medium |
| Discovery | clustered `net`, `ipconfig`, `systeminfo`, `tasklist`, `netstat`, `nltest`, `wmic logicaldisk` | Medium (baseline needed) |
| C2 over proxy | custom **FRP** / **Impacket**; sign-ins from unusual IPs via SOHO/edge proxies | Mixed |
| Initial access | exploited public-facing edge devices (Fortinet, Cisco, NETGEAR SOHO) | — |

> Atomic IOCs (FRP hashes, proxy IPs) churn fast and the KV-botnet was disrupted; populate hash placeholders from Microsoft/CISA and treat them as retro-hunt. The behaviors above are the durable signal.

## MITRE ATT&CK (Enterprise)

- **Initial Access** — Exploit Public-Facing Application (T1190); Valid Accounts (T1078)
- **Credential Access** — OS Credential Dumping: LSASS (T1003.001), NTDS (T1003.003)
- **Discovery** — System/Network/Account discovery (T1082, T1016, T1087)
- **Defense Evasion** — Indicator Removal / clear logs (T1070); LOTL via signed binaries
- **Command & Control** — Proxy: internal + multi-hop via SOHO (T1090.001, T1090.003); Compromise Infrastructure: botnet (T1584.005)
- **Collection / Exfil** — over C2 channel (T1041)

## Deployment notes

- **Logging is the prerequisite.** Enable command-line process auditing (and Sysmon EID 1), PowerShell ScriptBlock/Module logging, and registry auditing (Sysmon EID 12-14) for the PortProxy path. Without these, the host queries are blind.
- **Searches 1-3 are high-fidelity** (port proxy creation, NTDS install-media, LSASS comsvcs dump are genuinely rare). **Searches 4-5 require baselining** — they overlap with legitimate admin work; alerting on them raw will bury you.
- **Correlate, don't isolate.** Volt Typhoon's strength is that each step looks normal. The strongest detection is *clustering*: a portproxy + a discovery burst + an unusual sign-in for the same host/account in a short window.
- **The YARA is the weak leg by design.** The hash rule is inert until populated; the FRP rule is dual-use and hunt-only. Don't expect endpoint YARA to catch this actor.

## Sources

- CISA — [AA24-038A: PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- CISA — [AA23-144A: PRC State-Sponsored Cyber Actor Living off the Land to Evade Detection](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a)
- Microsoft — [Volt Typhoon targets US critical infrastructure with living-off-the-land techniques](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)
- MITRE ATT&CK — [G1017 (Volt Typhoon)](https://attack.mitre.org/groups/G1017/)
