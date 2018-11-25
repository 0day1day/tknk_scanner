rule win_hancitor_g2 {
    meta:
        module = "hancitor"
        author   = "mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $get_cfg0 = { 55 8B EC 83 3D [4] 00 74 ?? A1 [4] EB ?? 68 [4] E8 [4] 83 C4 04 A3 [4] 68 }
        $get_cfg1 = { A1 [4] 85 C0 75 ?? 5? BE 00 ?? 00 00 56 E8 0F ?8 ?? ?? 56 68 }
        $get_cfg2 = { A1 [4] 85 C0 75 ?? 68 [4] E8 [4] 68 [4] 68 [4] 5? A3 }
        $get_ua0  = { 55 8B EC 83 3D [4] 00 75 18 6A 00 6A 00 6A 00 6A 00 68 [4] FF 15 [4] A3 [4] A1 [4] 5D C3}
        $get_ua1 = {  85 ?? ?5 ?? 5? 5? 5? 5? 68 [4] FF 15 }

        $s0="api.ipify.org" fullword
        $reqest0="GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)" fullword
        $reqest1="GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)" fullword
        $reqest2="GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)" fullword
    condition:
        $s0 and 1 of ($reqest*) and any of them
}
