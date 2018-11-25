rule win_listrix_w0 {
    meta:
        author = "Florian Roth"
        reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "\\Update\\Temp\\ufiles.txt" fullword wide
        $s2 = "%02d.%02d.%04d %02d:%02d" fullword wide
        $s3 = "*pass*.*" fullword wide
    condition:
        all of them
}
