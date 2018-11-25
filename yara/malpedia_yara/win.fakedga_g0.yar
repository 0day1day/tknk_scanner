rule win_fakedga_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180220"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        // lethic
        //$ops_FakeDGA0 = { 33 D2  B9 19 00 00 00          F7 F1  8? C2 61  8B 45 F0 }
        //$str_C   = "_update0."
        // lethic (321599), fakedga
        //$str_1  = "dd.te" wide

        $str_c2a = "x%d.%s" fullword
        $str_c2b = "%s%u.%s" fullword
        $str_A   = ".local.backup"
        // lethic, fakedga, cycbot
        $str_B   = "DisableAntiSpyware"

        $ops_FakeDGA1 = { E8 [4] 6A 19           99  59  F7 F9  8? C2 61  88 54 35 C0  46  83 FE 07 }
        $ops_FakeDGA2 = { E8 [4] 8B 1? [4]  83 C4 04  8B F8  6A 3A  5?  C7 [3]  2E 16 00 00 }

    condition:
        2 of them
}
