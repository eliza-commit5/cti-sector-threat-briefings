/*
   IOCONTROL (aka OrpaCrab) — CyberAv3ngers (IRGC-CEC) OT/IoT backdoor
   Source: Claroty Team82, "Inside a New OT/IoT Cyberweapon: IOCONTROL" (Dec 2024)

   DETECTION REALITY CHECK
   -----------------------
   IOCONTROL ships UPX-packed (with a tampered magic) and stores its entire
   configuration — C2 domain, GUID, MQTT creds — AES-256-CBC encrypted inside
   the binary. That means the high-value atomic IOCs (tylarion867mino[.]com,
   the GUID, the C2 IP) are NOT present as plaintext in the packed file, so you
   cannot reliably string-match them on disk. Use those as NETWORK detections
   (see the SPL/KQL files). On-disk detection is therefore either:
     (a) exact-hash for the known sample, or
     (b) a weak heuristic on the tampered-UPX artifact (retro-hunt / triage only).

   Requires the YARA 'hash' module for rule iocontrol_known_sample_sha256.
*/

import "hash"

rule iocontrol_known_sample_sha256
{
    meta:
        description = "IOCONTROL/OrpaCrab — exact known sample (Claroty Team82)"
        author      = "Eliza / eliza-commit5"
        date        = "2026-06-11"
        reference   = "https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol"
        actor       = "CyberAv3ngers (IRGC-CEC)"
        malware     = "IOCONTROL / OrpaCrab"
        sha256      = "1b39f9b2b96a6586c4a11ab2fdbff8fdf16ba5a0ac7603149023d73f33b84498"
        confidence  = "high"
        tlp         = "CLEAR"
    condition:
        hash.sha256(0, filesize) ==
            "1b39f9b2b96a6586c4a11ab2fdbff8fdf16ba5a0ac7603149023d73f33b84498"
}

rule iocontrol_tampered_upx_elf_heuristic
{
    meta:
        description = "Heuristic: ELF packed with a tampered-magic UPX variant, as used by IOCONTROL. HIGH FALSE-POSITIVE RISK — triage/retro-hunt only, not endpoint blocking."
        author      = "[Your Name / Handle]"
        date        = "2026-06-11"
        reference   = "https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol"
        actor       = "CyberAv3ngers (IRGC-CEC)"
        malware     = "IOCONTROL / OrpaCrab"
        confidence  = "low"
        tlp         = "CLEAR"
    strings:
        // Team82 found the UPX magic 'UPX!' replaced with 'ABC!' in the packed
        // sample; the untouched little-endian artifact 'UPX!' -> '!XPU' was left
        // in an unpacked segment. Match either marker.
        $upx_real    = "UPX!"
        $upx_tamper  = "ABC!"
        $upx_le_art  = "!XPU"
        $upx_banner  = "$Info: This file is packed with the UPX"
    condition:
        // ELF that carries UPX packer structure but whose magic has been
        // tampered (real UPX magic absent while a substitute marker is present).
        uint32(0) == 0x464c457f                       // \x7fELF
        and filesize < 5MB
        and ( $upx_tamper or $upx_le_art )
        and not $upx_real
        and not $upx_banner
}

/*
   OPTIONAL — per-victim GUID (binary-patched, sample-specific)
   The sample's seed GUID 855958ce-6483-4953-8c18-3f9625d88c27 is patched per
   victim/campaign and is encrypted in the packed binary, so this will only hit
   on an UNPACKED artifact or memory capture of THIS sample. Enable for memory
   forensics, not for at-rest file scanning.

rule iocontrol_seed_guid_unpacked_memory
{
    meta:
        description = "IOCONTROL seed GUID (unpacked/memory only; sample-specific)"
        author      = "[Your Name / Handle]"
        reference   = "https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol"
        confidence  = "medium"
    strings:
        $guid = "855958ce-6483-4953-8c18-3f9625d88c27" ascii wide nocase
    condition:
        $guid
}
*/
