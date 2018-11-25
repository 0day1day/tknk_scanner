rule win_crashoverride_w6 {
    meta:
        description = "Identify service hollowing and persistence setting"
        author = "Dragos Inc"
        reference = "https://dragos.com/blog/crashoverride/"
        malpedia_version = "20170615"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s0 = { 33 c9 51 51 51 51 51 51 ?? ?? ?? }
        $s1 = { 6a ff 6a ff 6a ff 50 ff 15 24 ?? 40 00 ff ?? ?? ff 15 20 ?? 40 00 }
    condition:
        all of them
}
