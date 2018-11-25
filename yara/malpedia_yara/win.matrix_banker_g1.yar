rule win_matrix_banker_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170816"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_form1 = "%02u-%02u-%02u %02u:%02u:%02u"
        $str_form2 = "--------------------------%04x%04x%04x"
        $str_form3 = "%04x-%04x-%04x"
        $str_RefleciveLoader = "ReflectiveLoader"
        $str_main32 = "main_32.dll"
        $str_main64 = "main_64.dll"
        $str_conf1  = "targeturl="
        $str_conf2  = "rule1:"
        $str_conf3  = "rule2:"
        $str_conf4  = "&br&"

        $op_salsa20_key0   = { A1 9C 41 89 B4 9D 15 61 65 F1 61 8B 4C 51 6A 16 }
        $op_salsa20_key1   = { F1 6C 18 1D 81 B8 18 18 E1 81 65 1C 21 B8 5C 65 }
        $op_salsa20_m1  = { C7 0? 65 78 70 61 }
        $op_salsa20_m2  = { C7 43 28 6E 64 20 33 }
        $op_salsa20_m3  = { C7 43 50 32 2D 62 79 }
        $op_salsa20_m4  = { C7 43 78 74 65 20 6B }
        $op_32_salsa20_IV0a = { C7 8? ?? ?? FF FF FF 4B 84 8E 48 }
        $op_32_salsa20_IV0b = { C7 8? ?? ?? FF FF FF F1 5D 45 A5 }
        $op_32_salsa20_0   = { 99  C1 E6 08  0B F0     0F B6 47 01  81 E6 FF FF 00 00 99  0F A4 F1 08  C1 E6 08 } 
        $op_64_salsa20_IV0 = { C7 8? ?? ?? 00 00 00 4B 84 8E 48   C7 8? ?? ?? 00 00 00 F1 5D 45 A5 }
        $op_64_salsa20_0   = { 49 C1 E0 08   4C 0B C0  [6-10]  49 C1 E1 08  4C 0B C8  0F B6 02  49 C1 E1 08  4C 0B C8 } 

    condition:
        6 of ($str_*)
        or ( 3 of ($str_*) and 5 of ($op_*) )
}

