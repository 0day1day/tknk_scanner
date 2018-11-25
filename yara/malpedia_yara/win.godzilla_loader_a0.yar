rule win_godzilla_loader_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        kudos = "Raashid Bhat"
        malpedia_version = "20170420"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $ops_db       = { 6A 25 58 6A 73 66 89 45 ??  58 6A 2E 66 89 45 ??  58 66 89 45 ?? 6A 64  58 66 89 45 ?? 6A 62  58 }
        $ops_link     = { 6A 25 58 6A 73 66 89 45 ??  58 6A 5C 66 89 45 ??  58 6A 25 66 89 45 ??  58 6A 53 66 89 45 ??  58 6A 2E 66 89 45 ??  58 6A 6C 66 89 45 ??  58 }
        $ops_randfunc = { 6A 3E 99 59 F7 F9 83 FA 1A 7D 05 80 C2 61 EB 0D 83 FA 34 7D 05 80 C2 27 EB 03 80 EA 04 }
        $ops_tick     = { C7 45 ?? 85 F4 50 30  66 89 4D ??  C7 45 ?? CF 11 BB 82  C7 45 ?? 00 AA 00 BD  66 C7 45 ?? CE 0B  }
        $ops_godzilla = { 6A 47 [3-6] 6A 4F [3-6] 6A 44 [3-6] 6A 5A [3-6] 6A 49 [3-6] 6A 4C [3-6] 6A 4C [3-6] 6A 41 } 

    condition:
        $ops_godzilla or 2 of ($ops_*)
}
