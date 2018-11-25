rule win_makloader_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20181003"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_mutex  = "MAKtEMPmUTEX"
        $str_p02X   = "%%%02X"
        $str_88Xs   = "%08X%08X_%s"
        $str_cphp   = "/c.php?i="
        $str_cache  = "&cache=%d"
        $str_MARKER = "MDMARSRMRPKUZFLHKJNCYNNNMCVRQHMKIBWPFLCY"
        
        $op_DGA_lcg = { 69 45 A8 39 05 00 00  83 C0 01  33 D2  B9 8D 7A 00 00  F7 F1 }
        $op_gen_xor = { 0F BE 45 08  8B 4D FC  0F BE 11  33 C2 }

    condition:
        4 of them or
        (2 of them and $op_DGA_lcg)
}
