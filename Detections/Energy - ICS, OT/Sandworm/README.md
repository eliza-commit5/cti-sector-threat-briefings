# Sandworm (GRU Unit 74455 / APT44) — Detection Pack

> **TLP:CLEAR.** Detections compiled from primary reporting. Validate every indicator and rule against your own telemetry before operational use.

Maintained by **"Eliza / eliza-commit5"

Russian GRU Unit 74455 — tracked by Mandiant as **APT44**, and historically as Voodoo Bear / Telebots / Sandworm. The only confirmed actor with a track record of **destructive ICS attacks causing physical impact** (2015/2016 Ukraine grid outages, 2022 Industroyer2, 2024 FrostyGoop). Pairs OT-specific effects with Windows wipers and frequently operates through compromised network edge devices.

## Files

| File | Platform | What it covers |
|---|---|---|
| `sandworm_splunk.spl` | Splunk SPL | Unauthorized Modbus writes, internet-exposed Modbus, IEC-104 anomalies, L2TP-into-OT, hash retro-hunt |
| `sandworm_defender.kql` | Defender XDR / Sentinel | FrostyGoop hash + behavior, OT-protocol from Windows hosts, destructive-staging (shadow/boot tampering) |
| `frostygoop.yar` | YARA | Library-combo heuristic + hash rule for FrostyGoop/BUSTLEBERM |

## Signature capabilities

**FrostyGoop / BUSTLEBERM** — 9th known ICS-centric malware; first to use **Modbus TCP (port 502)** to cause physical impact. Go-compiled Windows binary; takes targets via command line or a **JSON config**; uses a rare `rolfl/modbus` library plus `goccy/go-json` and `hsblhsn/queues`. In January 2024 it disrupted heating to **600+ apartment buildings in Lviv, Ukraine** by downgrading ENCO controller firmware and forcing bad sensor readings. Can be run inside the perimeter or directly against internet-exposed Modbus devices.

**Industroyer2** (2022) — IEC 60870-5-104 (**port 2404**) malware used against a Ukrainian electric utility to trip breakers; deployed alongside the **CaddyWiper** wiper.

## Indicators of compromise

> **Validity warning:** atomic indicators churn fast. The durable signal is *behavioral* — unauthorized Modbus writes, IEC-104 from unexpected hosts, OT protocols crossing the perimeter. Populate the hash placeholders from primary IOC appendices.

| Type | Indicator | Notes |
|---|---|---|
| Protocol | Modbus TCP, **port 502** | FrostyGoop C2-to-device |
| Modbus func codes | 5, 6, 15, 16 (writes); 8 (diag); 43 (device ID) | Write/diagnostic = suspicious from non-masters |
| Protocol | IEC 60870-5-104, **port 2404** | Industroyer2 → RTUs |
| Initial access | L2TP (UDP/1701), MikroTik edge-router compromise | Lviv intrusion tradecraft |
| Library strings | `github.com/rolfl/modbus`, `github.com/goccy/go-json`, `github.com/hsblhsn/queues` | Embedded Go import paths — FrostyGoop identifier |
| Config | JSON with `TaskList`, `Iplist`, `Tasks`, `Code`, `Address`, `Count`, `Value`, `State` | FrostyGoop task structure |
| Hashes | **TO BE ADDED** | Paste verified SHA-256 from Dragos / Unit 42 |

## MITRE ATT&CK for ICS

- **Initial Access** — Exploit public-facing/edge device (T0819); Internet-accessible device (T0883)
- **Execution / Impair** — Modbus writes to manipulate registers; Modify Controller Tasking (T0821); Unauthorized Command Message (T0855)
- **Inhibit Response Function** — Firmware downgrade / Modify Program (T0843, T0889)
- **Impact** — Loss of Control / Loss of View (T0827, T0829); Denial of Control (T0813); Damage to Property (T0879)
- **Enterprise (paired tooling)** — Data Destruction / wipers (T1485); Inhibit System Recovery (T1490)

## Deployment notes

- **Modbus/IEC-104 parsing requires an OT-aware sensor** (Zeek with the Modbus/IEC-104 parsers, Dragos, Nozomi, or Defender for IoT). Raw firewall logs give port-level visibility only.
- **FrostyGoop staging is endpoint-visible.** Unlike a pure-PLC actor, the Go tool usually runs on a Windows engineering workstation, so `DeviceProcessEvents` / Sysmon coverage is genuinely useful (see KQL #2, SPL #5).
- **The YARA library-combo rule is medium-high confidence** and safe to run for hunting; the hash rule is inert until you add verified hashes (it contains an all-zero placeholder that never matches).
- **Tune every allow-list** (`approved_modbus_masters`, `approved_scada_masters`, sanctioned broker/master IPs) to your asset inventory before enabling.

## Sources

- Dragos — [Impact of FrostyGoop ICS Malware on Connected OT Systems](https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology)
- Unit 42 — [FrostyGoop's Zoom-In: Artifacts, Behaviors and Network Communications](https://unit42.paloaltonetworks.com/frostygoop-malware-analysis/)
- ESET / CERT-UA — Industroyer2 reporting (electric grid, IEC 60870-5-104)
- Mandiant — APT44 / Sandworm profile
