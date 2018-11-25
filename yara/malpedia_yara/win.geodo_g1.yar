rule win_geodo_g1 {
    meta:
        author = "mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $url_patt0 = "http%s://%%.%ds%%.%ds" ascii fullword
        $url_patt1 = "http://%u.%u.%u.%u:%u/%x/%d/" ascii fullword
        $bot_patt  = "%s_%s_%x%x" ascii fullword
        $generate_key = { (35 |81 F?) EC 5A 21 19 5? 8? ?? (35 | 81 F?) 9F 2D 89 41 5? 8? ?? (35 | 81 F?) 0B 73 3C 68 5? (35 | 81 F? ) E2 19 6B 7E}
        $get_ports = {5? 0F B7 ?? ?? [4] (5? | 8? [5] 5?)}
        $drop_threads = {6A 00 6A 00 6A 00 68 [4] 6A 00 6A 00 FF 15 [4] 6A 00 6A 00 6A 00 68 [4] 6A 00 6A 00 A3 [4] FF 15}
        $set_drop = { 8b ?? [4] 8d ?? ?? 70 c7  }
        $get_privkey = { 5? 6A 00 68 00 80 00 00 68 A2 00 00 00 68 [4] 6A 08 6A 01 C7}
        
    condition:
        (any of ($url_patt*)  and $bot_patt) or 
        ($generate_key and ($get_ports or $get_privkey)) or
        ($drop_threads and $set_drop)
}
