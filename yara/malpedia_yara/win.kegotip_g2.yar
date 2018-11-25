rule win_kegotip_g2 {
    meta:
        author = "mak / Slavo Greminger, SWITCH-CERT"
        kudos = "CCIRC Akira"
        malpedia_version = "20170412"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str1 = "VendorId"
        $str2 = "UuidCreate"
        $str3 = "*%x.exe" wide
        $str4 = "%s_%d"
        $str5 = "MSWQ*.tmp"
        $str6 = "SUCCESS" fullword
        $str7 = "_DEFAULT_"
        $str8 = "Asdj" fullword

        $url1 = "index_get.php?key="
        $url2 = "action=ADD_FTP"
        $url3 = "ftp_host=%s&ftp_login=%s&ftp_pass=%s"
        $url4 = "X-Real-IP:"

        $decode_loop = {8B ?? E8 0F B6 ?? [4] 8B ?? F8 0F B6 ?? 3? ?? 8B ?? F8 88 10 E? C?}
    condition:
        ( $decode_loop and 4 of ($str*) )
        or
        ( 4 of ($str*)) and (2 of ($url*) )
}
