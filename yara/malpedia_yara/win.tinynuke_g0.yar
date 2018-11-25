rule win_tinynuke_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170922"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_botid1   = "%08lX%04lX%lu"
        $str_botid1_w = "%08lX%04lX%lu" wide
        $str_botid2   = "%08lX-%04lX-%lu"
        $str_botid2_w = "%08lX-%04lX-%lu" wide
        $str_info     = "info|%d|%d|%d|%d|%s|%s|%d|%d"
        $str_bot32    = "bin|int32"
        $str_bot64    = "bin|int64"
        $str_log      = "log|%s|%s|%d|"
        $str_key      = "\\Registry\\User\\%s\\%s"
        $str_key_w    = "\\Registry\\User\\%s\\%s" wide
        $str_del      = "del \"%%~f0\""

        // too many fp
        // $op_layer_DeobjStr1 = { E8 [4] 8? [2] 8? [2] 85 ?? 0F 84 [4] A1 ?? ?? ?? ?? }
        // $op_xor_n           = { FF ?? 3B ?? 7C ?? A1 ?? ?? ?? ?? 89 }

        $op_api_hashing     = { C1 E0 07  C1 E9 03  33 C1  33 C6 }
        $op_payload         = { 0F B7 44 57 08  8B C8  C1 E8 0C  81 E1 FF 0F 00 00  83 F8 03 7? }
        $op_obfuscate1      = { F7 F1 8A 04 3A 30 04 1E 46 3B 75 0C }
        $op_obfuscate2      = { F7 F1 8B 45 0C 8B 4D 08 8A 04 02 32 04 31 }
        $op_memsetcrypt     = { 0F B6 45 0C   69 C0 01 01 01 01   56  8B F1  57  8B 7D 08  C1 E9 02  F3 AB }
        $op_string_xorkey1  = { 8B C7  99  F7 FB  68 [4]  47  8A 4? [2]  30 87 [4] FF }
        $op_string_xorkey2  = { FF 15 [4]  8B C8  8B 45 ??  33 D2  F7 F1  8B 45 0C [3-8] (32 | 33) [1-8] 88 ??  }
        $op_verifyPE        = { 81 7D 0C 00 04 00 00  76 ?? [0-14] 8? [1-2] 4D 75 } // [0-14] 8? [1-2] 5A }

        $unicorn_1          = "X-GrewUpAscrewUp: MaybeIdidntLoveYou"
        $unicorn_2          = "X-HeyThere: "

    condition:
        4 of them
        or ( 3 of ($op_*) )
        or ( 1 of ($unicorn_*))
}
