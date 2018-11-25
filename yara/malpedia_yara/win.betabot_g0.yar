rule win_betabot_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170816"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_neurevt = "neurevt"
        // $marker1  = { DC 3A 16 F7 B1 }
        // $marker2e = { 54 2E BB C9 FE }
        // $marker2f = { 54 2E BB C9 FF }

        $str_url1 = "%s?action=up&g=%s"
        $str_url2 = "ext="
        $str_url3 = "term="
        $str_url4 = "filename="
        $str_url5 = "exclude="
        $str_url6 = "nocache="

        // Betabot <= 1.7
        $str_betabot = "Betabot (c)" wide

        // Betabot > 1.7
        $black_u1 = "76487-640-1457236-23837"
        $black_u2 = "76487-337-8429955-22614"
        $black_u3 = "76487-644-3177037-23510"
        $black_u4 = "76497-640-6308873-23835"
        $black_u5 = "55274-640-2673064-23950"
        $black_u6 = "76487-640-8834005-23195"
        $black_u7 = "76487-640-0716662-23535"
        $black_u8 = "76487-644-8648466-23106"
        $black_u9 = "00426-293-8170032-85146"
        $black_uA = "76487-341-5883812-22420"
        $black_uB = "76487-OEM-0027453-63796"
        $black_n1 = ".kaspersky.com"
        $black_n2 = ".drweb.com"
        $black_n3 = "symantec.com"
        $black_n4 = ".avast.com"
        $black_n5 = ".avg.com"
        $black_n6 = ".pandasecurity.com"
        $black_n7 = ".nai.com"
        $black_n8 = "trendmicro.com"
        $black_n9 = ".avira.com"
        $black_nA = ".comodo.com"
        $black_nB = ".sophos.com"

        $op_rc4                = { 33 D2 33 C0 BF 00 01 00 00 88 04 08 40 3B C7 7C F8 66 89 91 00 01 00 00 }
        $op_xor1B_v151617      = { F6 C1 01 7? ??  80 74 ?? ?? 1B  41 3B C8  7? ??   8D 4C ?? ??  51 }
        $op_encodedecode_v15   = { 5? B8 46 0D 00 00  8B ??  8B ??  E8 [4]  BE C0 00 00 00  5? }
        $op_encodedecode_v1617 = { 8B ?? ?? BE 56 0D 00 00  5? 5? 5?  8D 8D [4]  E8 [4]  6A 04 }
        $op_xor1B_201x         = { F6 C1 01 7? ??  80 74 ?? ?? 1B  41 3B C8  7? ??   3D FF 00 00 00 7? 1? 8D 4C ?? ??  51 }
        $op_encodedecode_201x  = { 8B ?? ?? BE 24 01 00 00  (5?|8B ??)  (5?|8B ??) (5?|8B ??)  8D 8D [4]  E8 [4]  (6A 04|68 6B 03 00) }

    condition:
        7 of ($str_*)
        or 11 of ($black_*)
        or 2 of ($op_*)
}
