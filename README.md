# cti-sector-threat-briefings

# CTI Sector Threat Briefings

> **TLP:CLEAR** — May be shared without restriction. Compiled from open-source intelligence. Validate all indicators, CVEs, and attributions against the original CISA / FBI / NSA / NIST advisories before operational use.

![License: MIT](https://img.shields.io/badge/code-MIT-blue.svg)
![Reports: CC--BY--4.0](https://img.shields.io/badge/reports-CC--BY--4.0-lightgrey.svg)
![TLP: CLEAR](https://img.shields.io/badge/TLP-CLEAR-brightgreen.svg)
![Last updated](https://img.shields.io/badge/updated-June%202026-informational.svg)

Curated cyber threat intelligence briefings covering active campaigns, indicators of compromise (IOCs), and behavioral analysis for the **Energy / ICS-OT**, **ISP / Telecom**, and **Quantum** sectors — plus practical notes on leveraging AI in CTI workflows.

Maintained by **Eliza / eliza-commit5**. Contributions, corrections, and source links welcome via issues and pull requests.

---

## Contents

- [Reports](#Reports)
- [Executive summary](#executive-summary)
- [1. Energy / ICS-OT](#1-energy--ics-ot)
- [2. ISP / Telecom](#2-isp--telecom)
- [3. Quantum](#3-quantum)
- [4. Leveraging AI in threat intelligence](#4-leveraging-ai-in-threat-intelligence)
- [Sourcing discipline](#sourcing-discipline)
- [Repository structure](#repository-structure)
- [Using the IOCs](#using-the-iocs)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Reports

The full briefing is available as downloadable documents:

- [Full briefing (Word / .docx)](reports/CTI_Sector_Threat_Briefing.docx)

The sections below reproduce the briefing content so you can read it without leaving the page.

---

## Executive summary

| Sector | Bottom line |
|---|---|
| **Energy / ICS-OT** | Iranian (IRGC-CEC / CyberAv3ngers) and Russian (Sandworm) state actors dominate; a recent landscape assessment placed the energy/utilities sector in **66% of observed APT campaigns**. The threat is shifting from espionage toward disruptive/destructive OT impact. |
| **ISP / Telecom** | **Salt Typhoon** (PRC) remains the defining campaign — 600+ organizations across 80 countries. Detection must be **behavioral / TTP-based**; atomic IOCs are deliberately sparse, and stolen credentials (not exploits) were the most common initial-access vector. |
| **Quantum** | Two distinct threat models: (1) **Harvest Now, Decrypt Later** cryptographic collection active *today*, and (2) PRC economic espionage against quantum R&D firms. The threat is APT41-style IP theft and insider risk — not quantum-specific malware. |
| **AI in CTI** | Highest-leverage use cases: IOC enrichment/correlation, report-to-detection automation (Sigma/YARA/KQL), ingestion-time alert triage, the IOC→TTP shift, and closed-loop SIEM/SOAR/XDR operationalization. |

---

## 1. Energy / ICS-OT

The dominant theme is Iranian and Russian state activity against operational technology, with China-nexus espionage layered underneath. A recent landscape assessment found the energy and utilities sector was targeted in **66% of observed APT campaigns**, with Mustang Panda, Lazarus, and Sandworm remaining active.

### Active actors & campaigns

- **CyberAv3ngers (IRGC-CEC / Shahid Kaveh Group)** — most persistent OT threat to US infrastructure. CISA/FBI report ongoing campaigns since at least March 2026 against internet-exposed PLCs, including manipulating data shown on HMI/SCADA displays. Signature TTP: default-credential login on internet-exposed Unitronics PLCs via `TCP/20256`. Targets: water/wastewater, energy, fuel management.
- **Sandworm (GRU Unit 74455)** — the only confirmed actor with destructive ICS impact. FrostyGoop cut heating to 600+ buildings in Ukraine in winter 2024. Creates hacktivist proxy groups for deniable OT attacks.
- **Volt Typhoon (VOLTZITE)** — PRC pre-positioning, not espionage. CISA assesses pre-positioning for destructive attacks in a US–China conflict scenario, using exclusively living-off-the-land execution: `netsh`, `wmic`, `ntdsutil`, `PowerShell`. Use this as your LOTL hunting baseline.
- **APT34 / OilRig (MOIS)** — long-dwell energy access, currently assessed as covert pre-positioning. Hunt for low-frequency DNS anomalies and ASPX webshells on Exchange servers.

### Primary documentation

- CISA [AA23-335A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a) — CyberAv3ngers / Unitronics PLC targeting
- CloudSEK — [ICS/OT targeting assessment (Iran–US conflict, 2026)](https://www.cloudsek.com/blog/a-threat-actor-landscape-assessment-of-ics-ot-targeting-in-the-2026-iran-us-conflict-and-the-scale-of-the-risk)
- Kaspersky ICS-CERT — [Industrial threats, Q1 2026](https://ics-cert.kaspersky.com/publications/reports/2026/05/21/apt-and-financial-attacks-on-industrial-organizations-in-q1-2026/)
- Industrial Cyber — [energy sector APT coverage (66% figure)](https://industrialcyber.co/reports/energy-and-utilities-sector-targeted-in-66-of-observed-apt-campaigns-as-mustang-panda-lazarus-sandworm-remain-active/); also Dragos year-in-review reports

---

## 2. ISP / Telecom

This vertical is dominated by one campaign: **Salt Typhoon** (overlapping aliases: OPERATOR PANDA, RedMike, GhostEmperor, UNC5807, Earth Estries, FamousSparrow). PRC state-sponsored espionage against telecom backbones, affecting **600+ organizations across 80 countries**, including 200+ in the US.

The single most important resource is the joint advisory **CISA AA25-239A** (27 Aug 2025), which deliberately refers to the actors generically as "APT actors" to focus on behavior, not alias: [cisa.gov advisory](https://www.cisa.gov/news-events/alerts/2025/08/27/cisa-and-partners-release-joint-advisory-countering-chinese-state-sponsored-actors-compromise).

### Initial-access CVEs to prioritize

| CVE | Affected product | Description | ATT&CK |
|---|---|---|---|
| `CVE-2023-20198` | Cisco IOS XE Web UI | Authentication bypass (CVSS 10.0); creates unauthorized admin (priv 15) account. Chained with `CVE-2023-20273`. | T1133 / T1190 |
| `CVE-2023-20273` | Cisco IOS XE Web UI | Post-auth command injection / privilege escalation to root; writes implant to filesystem. | T1190 |
| `CVE-2018-0171` | Cisco Smart Install | Unauthenticated RCE (CVSS 9.8); ~7 years exploited in the wild. Port `TCP/4786`. | T1133 |
| `CVE-2023-46805` | Ivanti Connect Secure | Authentication bypass (CVSS 8.2); chained with `CVE-2024-21887`. | T1190 |
| `CVE-2024-21887` | Ivanti Connect / Policy Secure | Command injection (CVSS 9.1). | T1203 |
| `CVE-2024-3400` | Palo Alto PAN-OS GlobalProtect | Unauthenticated RCE / arbitrary file creation (CVSS 10.0). | T1190 |

> **Not exhaustive** — Fortinet, Juniper, Microsoft Exchange, Nokia, Sierra Wireless, and SonicWall devices may also be targeted.
>
> **Operational nuance:** Cisco Talos found that in all but one investigated incident, initial access used **valid stolen credentials, not exploitation** — do not over-index on CVE hunting alone.

### Behavioral analysis (post-compromise TTPs → MITRE ATT&CK)

- ACL modification to whitelist actor IPs — **Modify System Configuration (T1601)**
- TACACS+/RADIUS traffic capture for credential theft — **Modify Authentication Process (T1556)**
- GRE/IPsec tunneling for exfiltration — **Exfil Over Non-C2 Channel (T1048)**
- Detection-evasion tell worth a Sigma/Snort rule: "double encoding" on the Cisco IOS XE web UI, e.g. `/%77eb%75i`
- Payload note: the group avoids traditional malware, relying on LOTL; the **GhostSpider** backdoor is the notable exception

> **IOC caveat:** Confirmed atomic IOCs are deliberately sparse — practitioners report there is not enough to hunt on reliably to confirm removal. This is exactly why the campaign demands **behavioral / TTP detection over IOC matching**.

### Supplementary resources

- SafeBreach — [AA25-239A coverage](https://www.safebreach.com/blog/safebreach-coverage-for-cert-alert-aa25-239a/) (simulation + Snort/ATT&CK mapping)
- Picus — [AA25-239A analysis](https://www.picussecurity.com/resource/blog/cisa-alert-aa25-239a-analysis-simulation-and-mitigation-of-chinese-apts)
- Global Cyber Alliance — [Salt Typhoon Across the Internet](https://globalcyberalliance.org/new-report-salt-typhoon-across-the-internet/) (honeypot telemetry); also Recorded Future Insikt Group "RedMike" tracking

---

## 3. Quantum

This vertical splits into **two distinct threat models** that should be handled separately in your intelligence program.

### 3.1 Harvest Now, Decrypt Later (HNDL) — cryptographic threat

Not a forecast — an active collection operation. Adversaries collect encrypted data today and store it until future quantum computers can decrypt it, creating immediate risk for data that must stay confidential for years. The Global Risk Institute Quantum Threat Timeline (7th ed., March 2026) puts a cryptographically relevant quantum computer as "quite possible" within 10 years and "likely" within 15. Telecom and high-retention sectors (satellite, health) face the longest exposure windows — and Salt Typhoon's mass communications interception is itself a plausible HNDL collection vector.

### 3.2 IP theft against quantum companies — espionage threat

The FBI explicitly flags quantum computing in PRC collection priorities (alongside semiconductors, AI, ML), pursued via cyber intrusion, insider threats (Thousand Talents-style programs), and front companies. If you defend a quantum company, your threat model is **APT41-style economic espionage plus insider risk** — not exotic quantum-specific malware.

### Primary documentation

- **NIST FIPS 203 / 204 / 205** — finalized post-quantum cryptography standards; **NIST IR 8547** — RSA/ECC deprecation timeline (target 2035)
- **NSA CNSA 2.0** — NSS mandates; new NSS acquisitions expected to support CNSA 2.0 from 1 Jan 2027
- Cloud Security Alliance — [HNDL & AI infrastructure](https://labs.cloudsecurityalliance.org/research/ai-infrastructure-post-quantum-harvest-now-decrypt-later-v1/) (May 2026)
- CrowdStrike — [2026 Technology Threat Landscape Report](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-technology-threat-landscape-report/) (China-nexus targeting of tech/R&D); FBI — [Protecting Quantum Science & Technology](https://www.fbi.gov/news/stories/protecting-quantum-science-and-technology)

---

## 4. Leveraging AI in threat intelligence

The clearest near-term wins compress the research-to-detection pipeline. Concrete use cases where AI beats manual work:

1. **IOC enrichment & correlation.** Turning a raw indicator into context (attribution, campaign linkage, related infrastructure). Agentic tooling can compress days of research into minutes, transforming a single IOC into a hunting methodology.
2. **Report-to-detection automation.** Reading a narrative report and producing working detection logic — auto-generating Sigma, YARA/YARA-L, and KQL, and extracting behaviors to MITRE ATT&CK. See Microsoft Research's [CTI-REALM benchmark](https://techcommunity.microsoft.com/blog/azureinfrastructureblog/how-ai-agents-are-turning-threat-intelligence-into-validated-detections/4513971) (March 2026) for both tooling and a yardstick for vendor claims.
3. **Alert triage at ingestion.** Enriching every event at ingestion with AI-driven scoring (actor capability, target preference, success probability), shifting analysts from reactive processing to proactive hunting.
4. **IOC → TTP shift.** AI's real value is enabling the move from atomic IOCs to TTP-based intelligence, which lasts longer and is harder for adversaries to change — critical for behaviorally-driven actors like Salt Typhoon and Volt Typhoon.
5. **Closed-loop operationalization.** LLM-assisted pipelines linking CTI to SIEM/SOAR/XDR: automated enrichment, risk-scored detections, and conditional response that minimizes noise.

> **Honest caveat:** Treat vendor MTTD/MTTR percentages skeptically. Agents are good at *drafting* detections but still need human review and benchmarking (hence CTI-REALM), and adversaries use the same automation for polymorphic malware and deception.

**Resources to go deeper:** SANS CTI Summit — [AI Arms Race track](https://www.sans.org/webcasts/cti-ai-arms-race-building-resilient-adaptive-intelligence-platforms-2026) (vendor-neutral practitioner talks); MITRE ATT&CK as the structuring framework; STIX/TAXII for machine-readable exchange; open frameworks like CTI-REALM for evaluation.

---

## Sourcing discipline

- Anchor APT sections to **primary advisories** (CISA, FBI, NSA, NIST) over vendor blogs. Vendor write-ups are useful for ATT&CK mapping and simulation; advisories are authoritative.
- Several quantum-sector and AI-CTI sources are vendor-marketing-adjacent. Favor the independent ones flagged here (NIST, CSA, GRI, SANS).

---

## Repository structure

```
.
├── README.md                              # This briefing (the showcase)
├── LICENSE                                # MIT (code) — see License section
├── CHANGELOG.md                           # Date-stamped updates
├── reports/
│   ├── CTI_Sector_Threat_Briefing.pdf     # Renders inline on GitHub
│   └── CTI_Sector_Threat_Briefing.docx
└── iocs/
    ├── salt-typhoon-cves.csv              # Machine-readable CVE list
    └── salt-typhoon-iosxe.sigma           # Starter detection rule
```

---

## Using the IOCs

The `iocs/` directory provides machine-readable artifacts so you can operationalize this briefing rather than just read it:

- `salt-typhoon-cves.csv` — import into a spreadsheet, vulnerability tracker, or enrichment pipeline.
- `salt-typhoon-iosxe.sigma` — a starting detection for the Cisco IOS XE web UI "double encoding" evasion tell. **Tune and test against your own telemetry before deploying** — treat it as a hunting hypothesis, not a production rule.

---

## License

This repository uses a **dual license**:

- **Code and detection content** (anything in `iocs/`, scripts, rules) — [MIT License](LICENSE).
- **Written briefings and reports** (this README, files in `reports/`) — [Creative Commons Attribution 4.0 International (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/).

If you reuse or adapt the written analysis, please credit **[Your Name / Handle]** and link back to this repository.

---

## Disclaimer

This material is compiled from open-source reporting and is provided for defensive and educational purposes only. It is current as of **June 2026** and reflects the analyst's interpretation of public sources. Nothing here is authoritative — **validate every indicator, CVE, and attribution against the original vendor and government advisories before acting on it.** No warranty is expressed or implied.
