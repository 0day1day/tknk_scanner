rule win_kins_g0 {
    meta:
        author	 = "mak"
        contributor = "pnx"
        malpedia_version = "20170522"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        // $KINS_GetBaseConfig= { 8B 45 ?? 0F B6 00 8D 4D ?? ( 51 | ) FF 14 85 [4] 84 C0 }
        // $KINS_GetBaseConfig2= { 8B 4? ?? ?? 0F B6 00 8D 4? ?? ?? 51 FF 14 85 [4] 59 84 C0 }
        $get_AESkeyOff = { FF 75 08 33 C0 6A 05 40 5A}
        $KINS_GetBaseConfig2 ={ 8B 4? ?? 0F B6 00 8D 4? ??  51 FF 14 85 [4] 59 84 C0 }
        $ee_ = { 8B 54 24 04 8B 02 8A 08}
        $xx_ = {  20 30 F9 7F  3F 30 F9 7F}

        $push_cnc_field_0 = { 68 10 27 00 00 }
        $push_cnc_field_1 = { 68 11 27 00 00 }

    condition:
        ($get_AESkeyOff or $KINS_GetBaseConfig2 or $ee_ or $xx_) and (all of ($push_cnc_field_*))
}

