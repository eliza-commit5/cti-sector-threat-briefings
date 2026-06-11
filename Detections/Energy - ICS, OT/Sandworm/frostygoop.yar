/*
   FrostyGoop / BUSTLEBERM — Sandworm (GRU Unit 74455 / APT44)
   Go-compiled ICS malware that speaks Modbus TCP to manipulate OT devices.
   Sources:
     - Dragos: https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology
     - Unit 42: https://unit42.paloaltonetworks.com/frostygoop-malware-analysis/

   DETECTION BASIS
   ---------------
   Unit 42 notes FrostyGoop is built in Go and imports a set of UNUSUAL
   open-source libraries — a rolfl/modbus implementation plus goccy/go-json and
   hsblhsn/queues. Go binaries embed full import paths, so this rare combination
   is a strong, low-false-positive identifier. Pair with the hash rule once you
   have verified samples.

   Requires the YARA 'hash' module for frostygoop_known_hashes.
*/

import "hash"

rule frostygoop_golang_library_combo
{
    meta:
        description = "FrostyGoop/BUSTLEBERM — Go Modbus malware identified by rare imported library paths"
        author      = "Eliza / eliza-commit5"      
        date        = "2026-06-11"
        reference   = "https://unit42.paloaltonetworks.com/frostygoop-malware-analysis/"
        actor       = "Sandworm (GRU Unit 74455 / APT44)"
        malware     = "FrostyGoop / BUSTLEBERM"
        confidence  = "medium-high"
        tlp         = "CLEAR"
    strings:
        $go        = "Go build ID:" ascii
        $lib_mb    = "github.com/rolfl/modbus" ascii
        $lib_json  = "github.com/goccy/go-json" ascii
        $lib_queue = "github.com/hsblhsn/queues" ascii
        $s_task    = "TaskList" ascii
        $s_iplist  = "Iplist" ascii
    condition:
        // PE or ELF, Go-compiled, with at least two of the rare library paths.
        ( uint16(0) == 0x5a4d or uint32(0) == 0x464c457f )
        and $go
        and ( 2 of ($lib_*) )
        and ( 1 of ($s_*) )
}

rule frostygoop_known_hashes
{
    meta:
        description = "FrostyGoop/BUSTLEBERM — exact known sample hashes. ADD VERIFIED SHA-256 VALUES from the Dragos / Unit 42 IOC appendices before relying on this rule."
        author      = "Eliza / eliza-commit5"
        date        = "2026-06-11"
        reference   = "https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology"
        actor       = "Sandworm (GRU Unit 74455 / APT44)"
        malware     = "FrostyGoop / BUSTLEBERM"
        confidence  = "high"
        tlp         = "CLEAR"
    condition:
        // <-- ADD VERIFIED HASHES: replace the placeholder lines below with real
        //     SHA-256 values, e.g.:
        //         hash.sha256(0, filesize) == "abc123...def" or
        //         hash.sha256(0, filesize) == "111222...333"
        // Placeholder is intentionally false so the rule compiles but never fires
        // until you populate it.
        hash.sha256(0, filesize) == "0000000000000000000000000000000000000000000000000000000000000000"
}
