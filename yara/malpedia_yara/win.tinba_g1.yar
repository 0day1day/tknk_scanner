rule win_tinba_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170717"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $v2014_pkb = "BEGIN PUBLIC KEY"
        $v2014_pke = "END PUBLIC KEY"
        $v2014_re_config = /\x40\x00\x83\xc4\x0c\xc9\xc3\x90{0,16}[0-9a-zA-Z.\x00]{30}..\/[0-9a-zA-Z.\/\x00]{31}[0-9a-zA-Z]{16}/

        // 2014 (v2,v3) and 2017 (v4)
        $op_dga = { 02 07  30 D0  02 47 01  3C 61  76 04 3C 7A  72 04  FE C2  EB ED  AA E2 EA }

        // 2017 0f6a065a95e7428118d847a50eb4ef29 (TLP AMBER)
        // might be very overfitted
        $op_GZDF = { AD 89 C1 AD  3D 47 5A 44 46 7? ??  AD  83 F8 18  7? ?? 29 C1 AD 39 C8 }
        $op_xorror = { AC 30 D0 AA C1 CA 08 E2 F7 61 C9 C2 10 00 }
        $op_zlib = {  E8 [4] 08 0F 0E 0D 0C 0B 0A 09 07 06 05 04 03 02 01 10 11 12 00 }
        $op_rc4key1 = { 93  AC  11 40 00  8? 8? [4] 8? 8? [4]  33 01 33 41 04 33 41 08 33 41 0C }
        $op_rc4key2 = { 6A 64  FF 93 [4]  8? B? [4]  B9 10 00 00 00  31 C0  31 D2 }
        $op_rc4key3 = { AD  5?  5?  6A 10  5?  8? 8? [4]  87 04 24  E8 ?? ?? 00 00 } 

    condition:
        (all of ($v2014_*)) or
        (2 of ($op_*))
}

