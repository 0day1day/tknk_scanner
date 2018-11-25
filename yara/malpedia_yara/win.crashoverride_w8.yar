rule win_crashoverride_w8 {
    meta:
        description = "File manipulation actions associated with CRASHOVERRIDE wiper"
        author = "Dragos Inc"
        reference = "https://dragos.com/blog/crashoverride/"
        malpedia_version = "20170615"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s0 = { 6a 00 68 80 00 00 00 6a 03 6a 00 6a 02 8b f9 68 00 00 00 40 57 ff 15 1c ?? ?? ?? 8b d8 }
        $s2 = { 6a 00 50 57 56 53 ff 15 4c ?? ?? ?? 56 }
    condition:
        all of them
}
