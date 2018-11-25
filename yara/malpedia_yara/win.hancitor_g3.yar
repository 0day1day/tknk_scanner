rule win_hancitor_g3 {
    meta:
        module = "hancitor"
        author   = "mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $text = ".text" fullword
        $decoder_loop0 = {8B ?? 08 03 ?? FC 89 ?? F8 8B ?? F8 0F B6 ?? 83 F? ?? 8B ?? F8 88 0A}
        $decoder_loop1 = {8B ?? 10 33 c0 85 ?? 74 09 80 34 30 ?? 40 3B c1 72 f7}

        $s0="api.ipify.org" fullword
        $reqest0="GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)" fullword
        $reqest1="GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)" fullword
        $reqest2="GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)" fullword
    condition:
        $s0 and 1 of ($reqest*) and $text and 1 of ($decoder_loop*)
}
