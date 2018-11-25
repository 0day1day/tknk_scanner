rule win_crashoverride_w4 {
    meta:
        description = "CRASHOVERRIDE v1 Config File Parsing"
        author = "Dragos Inc"
        reference = "https://dragos.com/blog/crashoverride/"
        malpedia_version = "20170615"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s0 = { 68 e8 ?? ?? ?? 6a 00 e8 a3 ?? ?? ?? 8b f8 83 c4 ?8 }
        $s1 = { 8a 10 3a 11 75 ?? 84 d2 74 12 }
        $s2 = { 33 c0 eb ?? 1b c0 83 c8 ?? }
        $s3 = { 85 c0 75 ?? 8d 95 ?? ?? ?? ?? 8b cf ?? ?? }
    condition:
        all of them
}
