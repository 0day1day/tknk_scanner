rule win_crashoverride_w7 {
    meta:
        description = "Registry Wiper functionality assoicated with CRASHOVERRIDE"
        author = "Dragos Inc"
        reference = "https://dragos.com/blog/crashoverride/"
        malpedia_version = "20170615"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s0 = { 8d 85 a0 ?? ?? ?? 46 50 8d 85 a0 ?? ?? ?? 68 68 0d ?? ?? 50 }
        $s1 = { 6a 02 68 78 0b ?? ?? 6a 02 50 68 b4 0d ?? ?? ff b5 98 ?? ?? ?? ff 15 04 ?? ?? ?? }
        $s2 = { 68 00 02 00 00 8d 85 a0 ?? ?? ?? 50 56 ff b5 9c ?? ?? ?? ff 15 00 ?? ?? ?? 85 c0 }
    condition:
        all of them
}
