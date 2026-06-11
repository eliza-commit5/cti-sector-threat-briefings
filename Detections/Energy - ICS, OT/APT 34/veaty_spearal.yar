/*
   APT34 / OilRig (MOIS) — Veaty & Spearal .NET backdoors
   Source: Check Point Research, "Targeted Iranian Attacks Against Iraqi
   Government Infrastructure" (Sep 2024)
   https://research.checkpoint.com/2024/iranian-malware-attacks-iraqi-government/

   DETECTION BASIS
   ---------------
   Both backdoors are .NET and carry distinctive plaintext markers from their
   custom C2 protocols and configuration handling:
     - Spearal: DNS-tunneling protocol verbs (auth/cmd/crs/crb/cre) + config
       keys (srvip, domn, chunk_len) + default domain iqwebservice.
     - Veaty: Exchange/EWS email-C2 connection flags (try_*Creds) + the
       hardcoded typo-squat host mail.miicrosoft.com + mailbox-rule config keys.
   These are strong, low-false-positive identifiers. Pair with the hash rule
   once you have verified samples from the Check Point appendix.

   Requires the YARA 'hash' module for apt34_iraq_campaign_hashes.
*/

import "hash"

rule apt34_spearal_dns_backdoor
{
    meta:
        description = "APT34/OilRig Spearal — .NET DNS-tunneling backdoor (Veaty/Spearal campaign)"
        author      = Eliza / eliza-commit5
        date        = "2026-06-11"
        reference   = "https://research.checkpoint.com/2024/iranian-malware-attacks-iraqi-government/"
        actor       = "APT34 / OilRig (MOIS)"
        malware     = "Spearal"
        confidence  = "high"
        tlp         = "CLEAR"
    strings:
        $proto_auth = "auth:;" ascii wide
        $proto_crs  = "crs:;"  ascii wide
        $proto_crb  = "crb:;"  ascii wide
        $proto_cre  = "cre:;"  ascii wide
        $proto_rok  = "rok:;"  ascii wide
        $cfg_srvip  = "srvip"  ascii wide
        $cfg_domn   = "domn"   ascii wide
        $cfg_chunk  = "chunk_len" ascii wide
        $dom        = "iqwebservice" ascii wide
    condition:
        uint16(0) == 0x5a4d
        and filesize < 5MB
        and ( 3 of ($proto_*) )
        and ( 1 of ($cfg_*) or $dom )
}

rule apt34_veaty_email_backdoor
{
    meta:
        description = "APT34/OilRig Veaty — .NET Exchange/EWS email-C2 backdoor (Veaty/Spearal campaign)"
        author      = Eliza / eliza-commit5
        date        = "2026-06-11"
        reference   = "https://research.checkpoint.com/2024/iranian-malware-attacks-iraqi-government/"
        actor       = "APT34 / OilRig (MOIS)"
        malware     = "Veaty"
        confidence  = "high"
        tlp         = "CLEAR"
    strings:
        $flag1 = "try_defaultcred"   ascii wide
        $flag2 = "try_hardcodedCreds" ascii wide
        $flag3 = "try_externalCreds"  ascii wide
        $flag4 = "try_trustedNetwork" ascii wide
        $host  = "mail.miicrosoft.com" ascii wide          // typo-squat (two i's)
        $cfg1  = "placeForSignature"   ascii wide
        $cfg2  = "communicationFolder" ascii wide
        $cfg3  = "mail_domain_external_known" ascii wide
        $ews   = "/EWS/exchange.asmx"  ascii wide nocase
    condition:
        uint16(0) == 0x5a4d
        and filesize < 5MB
        and ( 2 of ($flag*) )
        and ( $host or 1 of ($cfg*) or $ews )
}

rule apt34_iraq_campaign_hashes
{
    meta:
        description = "APT34/OilRig Veaty/Spearal/CacheHttp.dll — exact sample hashes. ADD VERIFIED SHA-256 VALUES from the Check Point appendix before relying on this rule."
        author      = Eliza / eliza-commit5
        date        = "2026-06-11"
        reference   = "https://research.checkpoint.com/2024/iranian-malware-attacks-iraqi-government/"
        actor       = "APT34 / OilRig (MOIS)"
        confidence  = "high"
        tlp         = "CLEAR"
    condition:
        // <-- ADD VERIFIED HASHES: replace the placeholder with real SHA-256s, e.g.
        //   hash.sha256(0, filesize) == "abc...def" or
        //   hash.sha256(0, filesize) == "111...222"
        // The placeholder below is intentionally false so the rule compiles but
        // never fires until populated.
        hash.sha256(0, filesize) == "0000000000000000000000000000000000000000000000000000000000000000"
}
