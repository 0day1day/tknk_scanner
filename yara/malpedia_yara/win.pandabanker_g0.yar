rule win_pandabanker_g0 {
    meta:
        author="slavo/mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $access_enc_0 = { C6 [2-3] 01  8B D9  C7 [2-3] [4] 6A 00 42 C7 [2-3] [2] 00 00 }
        // $access_enc_1 = { 6A 00 42 C7 45 FC [2] 00 00  8D 4D F4  E8 [4] 8B D0 8B CA E8 [4] 84 C0 74 19 }
        $get_pubkey = { C6 45 F0 01 33 ?? C7 45 F4 [4] 5? 4? 89 [2] E8 [4] 8B F8 8B CF E8 }
    condition:
        any of them
}
