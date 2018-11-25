rule win_isfb_a3 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180104"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $ops_32_BuildNumber_a1 = { 5? (A1 [3] ?? |8B [1-4] ??) 0F C? 5? (A1 [3]??|8B [1-4] ??) 0F C? 5? (A1 [3] ??|8B [1-4] ??) 0F C? 5? 68 [4] (5?|6?) }
        $ops_32_BuildNumber_a2 = { 0F B6 C4 C1 E1 08 03 C8 51 68 [4] 68 }
        $ops_32_BuildNumber_b  = { (FF ?? ?? | FF 35 [3] ??)  FF 35 [4] FF 35 [4] 68 [4] 68 [4] (68|FF 75) }

        $ops_32_compilation_date_0             = { 8B (4?|5?) 10 [0-1] BE [4] 8D ?? ?? A5 A5 [0-3] A5 }
        $ops_32_compilation_date               = { 8B (4?|5?) 10 [0-9] BE [4] 8D ?? ?? A5 A5 [0-3] A5 }
        $ops_32_compilation_date_key_add_value = { 33 (45 E0|75 EC) [2-3] 83 C? [1] (03 F2|56 51) }


        // mov movBV(fix00)
        $ops_64_BuildNumber_a0  = { 89 (4C|54) 24 ??  41 B8 [3] 00  89 44 24 ??  8B }
        // mov lea mov2 mov movBV call
        $ops_64_BuildNumber_a1a = { 89 (4C|54) 24 2?  48 8D 1? [4]  41 B? 02 00 00 00  4? 8? C?   (41 B?|C7 44 24 20 ) [4]           FF 15 }
        // mov lea mov2 movBV mov call
        $ops_64_BuildNumber_a1b = { 89 (4C|54) 24 2?  48 8D 1? [4]  41 B? 02 00 00 00  (41 B?|C7 44 24 20 ) [4]  4? 8? C?            FF 15 }
        // mov lea mov movBV call
        $ops_64_BuildNumber_a2a = { 89 (4C|54) 24 2?  48 8D 1? [4]                     4? 8? C?   (41 B?|C7 44 24 20 ) [4]           FF 15 }
        // mov lea movBV mov call
        $ops_64_BuildNumber_a2b = { 89 (4C|54) 24 2?  48 8D 1? [4]                     (41 B?|C7 44 24 20 ) [4]  4? 8? C?            FF 15 }
        // mov lea movBV call
        $ops_64_BuildNumber_a3  = { 89 (4C|54) 24 2?  48 8D 1? [4]                     (41 B?|C7 44 24 20 ) [4]                      FF 15 }
        // mov lea movBV mov mov call
        $ops_64_BuildNumber_a4  = { 89 (4C|54) 24 2?  48 8D  [5-6]                     (41 B?|C7 44 24 20 ) [4]  4? 8? C?   4? 8? C? FF 15 }
        // bswap*3 movBV(fix00)
        $ops_64_BuildNumber_b1  = { (41 0F|0F) CA  (41 0F|0F) C9  (41 0F|0F) C?  41 B? [3] 00 }
        // mov lea mov swap movBV(fix00)
        $ops_64_BuildNumber_b2  = { 89 (4C|54) 24 2?  48 8D 1? [4]  49 8B CC  (41 0F|0F) C?  41 B? [3] 00 }
        // mov lea swap movBV(fix00)
        $ops_64_BuildNumber_b3  = { 48 8D 1? [4]  (41 0F|0F) C?  41 B? [3] 00 FF 15 }
        // additional obf, special case
        $ops_64_BuildNumber_c1  = { 41 0F B7 ?? 08  (8B ??|0F B7 ??)  E8 [4]  41 0F B7 ?? 06  (8B ??|0F B7 ??)  E8 [4]  41 0F B7 ?? 04  (8B ??|0F B7 ??)  E8 }
        // special case
        $ops_64_BuildNumber_c2  = { 48 8D 1? [4]  41 B? [3] 00  C7 44 24 20 [4]  FF 15 }

        // lea (xor|add|movmov) xor xor
        $ops_64_compilation_date_1 = { (44 8D|8D) (2C|3C) ??     33 C9                  (44 33|33) (6C|7C) 24 ?0  (44 33|33) (6C|7C) 24 ?4 }
        // lea add xor xor
        $ops_64_compilation_date_2 = { (44 8D|8D) (2C|3C) ??     48 [2]                 (44 33|33) (6C|7C) 24 ?0  (44 33|33) (6C|7C) 24 ?4 }
        $ops_64_compilation_date_3 = { (44 8D|8D) (2C|3C) ??     48 8B 0? [4] 4C 8B ??  (44 33|33) (6C|7C) 24 ?0  (44 33|33) (6C|7C) 24 ?4 }
        // additional obf, special case
        $ops_64_compilation_date_4 = { C1 E8 0C  8B CB    03 42 0C                  33 44 24 ?0  33 44 24 ?4 }


        // type
        $str_client = "client.dll"
        $str_loader = "loader.dll"
        $str_S      = "\"%S\""
        // before ".bss"
        $str_task   = "/task.php?"
        $str_data   = "/data.php?"
        $str_config = "/config.php?"
        // t/d/c or g/r/q or l/m/k
        $str_s_php  = /\/[a-z]%s\.php\?%s=/
        $str_s      = /\/[a-z]%s\?%s=/
        // unencrypted ".bss"
        $str_soft   = "soft=%u&version=%u&user=%08x%08x%08x%08x"
        $str_images = "/images/"


    condition:
       (1 of ($ops_32_Build*) and 1 of ($ops_32_comp*))
       or (1 of ($ops_64_Build*) and 1 of ($ops_64_comp*))
       or (1 of ($ops_*) and 2 of ($str_*))
}
