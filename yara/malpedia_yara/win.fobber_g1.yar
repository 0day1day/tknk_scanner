rule win_fobber_g1 {
    meta:
        author = "Daniel Plohmann / Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170802"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $str_key="9SsTuUknCWB1k0R"
        $str_reghole1="MisterBinGoodJob"
        $str_reghole2="Yes?"
        $str_reghole3="HelloHello"

        $op_init            = { 8B 45 0C  2B 45 10  2D [4]  89 45 FC  68 [4]  6A 0? }
        $op_findExplorer    = { 6A 00 50 FF 93 ?? ?? ?? ?? 85 C0 74 ?? 8D 55 ?? 52 50 FF 93 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 4D ?? 41 51 (6A ??|68 ?? ?? ?? ??) (6A ??|68 ?? ?? ?? ??) 8D 93 ?? ?? ?? ??}
        
        /***** loop for function decryption
           core of this function that is hopefully robust enough for detection:
           xor [reg], reg
           ror reg, 3
           add reg, 0x53
           inc reg
           loop
        */
        $op_decrypt_code    = { 55 89 E5 5? 8B ?? ?? 8B ?? ?? 8B ?? ?? 30 02 C0 C8 03 04 53 4? E2 }
        
        /*****  resolve address layout
           happens in more than one place. what we detect here:
           call $+5
           pop reg
           sub reg, offset
           return
        */
        $op_resolve_mapping = { E8 00 00 00 00 5? (81 ?? ?? ?? ?? ?? | 2D ?? ?? ?? ??) C3}

    condition:
       3 of ($str_*) or
       ( 2 of ($op_*) and #op_resolve_mapping > 1 )
}

