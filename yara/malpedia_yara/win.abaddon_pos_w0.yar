rule win_abaddon_pos_w0 {
    meta:
        author = "Darien Huss, Proofpoint"
        description = "AbaddonPOS"
        reference = "md5,317f9c57f7983e2608d5b2f00db954ff"
        malpedia_version = "20180322"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "devil_host" fullword ascii
        $s2 = "Chrome" fullword ascii
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
        $i1 = { 31 ?? 81 ?? 55 89 E5 8B 74 }
    condition:
        all of ($s*) or $i1
}
