rule win_dented_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171115"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_UA    = "icel" 
        $str_comm1 = "&version=" 
        $str_comm2 = "&gpu=" 
        $str_comm3 = "&isAdmin=" 
        $str_comm4 = "&arch=" 
        $str_comm5 = "&space=" 
        $str_comm6 = "&bot_id=" 
        $str_comm7 = "&cmd_id=" 
        $str_comm8 = "&cmd_status=" 

        $ops_getkey = {  0F B6 ?? [4]  89 84 8D FC F7 FF FF  41  81 F9 00 01 00 00  7C D?  33 D2  }

    condition:
        7 of ($str_*) or
        3 of ($str_*) and 1 of ($ops_*)
}
