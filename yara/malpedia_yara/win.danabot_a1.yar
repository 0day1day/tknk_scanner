rule win_danabot_a1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "loader"
        malpedia_version = "20180619"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $str_DoIn     = "DownloadInstall" fullword
        $str_O8       = "&=O8" 
        $str_b32      = "&b=32&c="
        $str_b64      = "&b=64&c="
        $str_Ord1     = "#1" wide fullword
        $ops_callOrd1  = { 8D 4D D?  BA [4]  A1 [4]  E8 }

        $ops_DownloadInstall = { 6A 00  6A 00  49  75 ??  5? 5? 5?  33 C0  5?  68 [4]  64 FF 30  64 89 20 B8 03 00 00 00 E8 }
    condition:
        4 of them
        or (3 of them and any of ($ops_*))
}

