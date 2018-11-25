rule win_geodo_a2 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180709"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        // easy spotted via CreateMutexW
        $crypt_ops1    = { 8D ?? ?? 33 ?? ?? 8D ?? ?? 0F ?? ?? 4? }
        $crypt_ops2a   = { 8B C? C1 ?? ?? [0-3] 0F ?? ?? 66 [3] C1 ?? ?? [0-3] 0F ?? ??  66 [3]  C1 ?? ?? [0-3] 0F ?? ?? 66  }
        $crypt_ops2b   = { 8B C? C1 ?? ?? [0-3] 0F ?? ?? 66 [3] C1 ?? ?? [0-3] 0F ?? ??  C1 ?? ?? [0-3] 66 [3]  0F ?? ?? 66  }
        $crypt_ops3    = { C1 ?? 02  33 C0  [4-8]  8B ??  2B ??  83 ?? 03  C1 ?? 02  3B ?? 0F }
        // xor lea .. shr 8 shr 10 [inc] shr 8 ...
        $crypt_opsG    = { 81 F2 [4]  8D 7? (0?|1?)  [0-8] 8B C2  C1 E8 08  [0-8]  C1 EA 10  [0-8]  C1 EA 08 }

        $prep_AZaz09_1 = { 83 F8 30 7? ??  83 F8 39 7? ??  83 F8 61 7? ??  83 F8 7A 7? ??  83 F8 41 7? ??  83 F8 5A }
        $prep_AZaz09_2 = { 66 83 FF 5A 76 F3 B9 61 00 00 00 66 89 08 41 83 C0 02 66 83 F9 7A 76 F3 B9 30 00 00 00 }
        $prep_AZaz09_3 = { 3C 30 7? ??  3C39 7? ??  3C 61 7? ??  3C 7A 7? ??  3C 41 7? ??  3C 5A }
        $prep_HttpSend = { B? 00 C3 4C 84  [0-8]  5?  33 FF  B? 00 C3 CC 84 }

    condition:
        any of ($crypt_*) and any of ($prep_*)
}
