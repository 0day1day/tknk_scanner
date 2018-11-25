rule win_jaff_g2 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        kudos = "@pnx"
        malpedia_version = "20170719"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_fs = { 5C 00 00 00 2A 00 2E 00 2A 00 00 00 2E 00 00 00 2E 00 2E 00 00 00 }
        $str_ID5 = "[ID5]"
        $str_IDf = "%0.10lu"
        $str_random = "[random"
        $str_form = "[/form]"

        $op_lcg1 = { 69 C0 FD 43 03 00  05 C3 9E 26 00  A3 [4]  C1 E8 10  25 FF 7F 00 00 } 
        $op_lcg2 = { 69 C9 FD 43 03 00  81 C1 C3 9E 26 00  8B C1  C1 E8 10  25 FF 7F 00 00 } 
        $op_fs = { 5C 00 00 00 2A 00 2E 00 2A 00 00 00 2E 00 00 00 2E 00 2E 00 00 00 }
        $op_crypt = { 89 45 FC 8D 45 FC  50 6A 00 6A 00 6A 01 6A 00 51 FF 15 [4] 85 C0 75 0C FF 15 }

        //$fun_typo1 = "After instalation"
        //$fun_typo2 = "decrypt flies"

    condition:
        4 of ($str_*) or
        2 of ($op_*)
}
