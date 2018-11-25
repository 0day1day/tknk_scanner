rule win_kardonloader_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180620"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $str_hello  = "rqf" fullword
        $str_post   = "id=%s&os=%s&pv=%s&ip=%s&cn=%s&un=%s&ca=%s"
        $str_notask = "notask"

        $ops_prng   = { A1 [4]  69 C0 FD 43 03 00  05 C3 9E 26 00  A3 [4]   C1 E8 10  25 FF 7F 00 00 }
        $ops_fname  = { E8 [4]  33 D2  6A 3E  59  F7 F1  8A 82 [4]  88 04 1F  47 }
        $ops_math17 = { B9 87 D6 12 00  8A 02  84 C0  7? ?? 5?  C1 E1 04  0F BE C0  03 C8 }
    condition:
        3 of them
}

