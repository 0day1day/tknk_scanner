rule win_hancitor_g1 {
    meta:
        module = "hancitor"
        author   = "mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $get_cnc0 = { C7 05 [4] [4] B? 01 00 00 00  85 C? 74 ?? 8B ?? [4] 0F BE ?? 83 F? 7C }
        $get_cnc1 = { A1 [4] B? [4] 85 C? 0F 45 ?? 89 0? [4] 8B 55 08 8A 01 3C 7C }

        $get_ua0  = { 55 8B EC 83 3D [4] 00 75 18 6A 00 6A 00 6A 00 6A 00 68 [4] FF 15 [4] A3 [4] A1 [4] 5D C3}
        $get_ua1 = { A1 [4] 85 C0 75 14 50 50 50 50 68 [4] FF 15 [4] A3 [4] C3 }

        $s0="api.ipify.org" fullword
        $reqest0="GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)" fullword
        $reqest1="GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)" fullword
        $reqest2="GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)" fullword
    condition:
        $s0 and 1 of ($reqest*) and 1 of ($get_cnc*) and 1 of ($get_ua*)
}
