rule win_vawtrak_g1 {
    meta:
        author = "mak"
        module = "vawtrak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $get_version = {A1 5? E0 ?? ?? 8D 4F 10 }
        $dga = { 8B E9 E8 [4] 6A 05 5? 33 D2 F7 F1 [4] E8 [4] [4] 83 E6 01 83 C7 07 }
        
    condition:
        all of them
}
