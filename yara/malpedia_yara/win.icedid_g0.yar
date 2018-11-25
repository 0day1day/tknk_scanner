rule win_icedid_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171114"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        // 289891 (Jul 2017)
        $str_c2a     = "&%c=%u"
        $str_uuuuP   = "[%0.2u:%0.2u:%0.2u] %u|"
        $str_sPsPs   = "%s|%s|%s"
        $str_sPP     = "%s||\x0D\x0A\x00"
        $str_tmp     = "\\%0.8X.tmp"
        $str_error   = "ERROR_2"
        $str_front   = "front://"

        $str_support = "support-%0.8X" wide
        $str_ipc     = "\\\\%s\\IPC$" wide
        $str_admin   = "\\\\%s\\ADMIN$" wide

        $ops_bind    = { 66 8B CF  8B C7  C1 E0 08  66 C1 E9 08  66 33 C8  }
        $ops_crypt   = { 8B 45 08  0F b7 40 04  33 45 F4  66 89 45 F8  8B 45 08  83 C0 06 }
        //$ops_ror2a    = { BD ?? ?? 00 00  8A 04 1A  D1 C9  F7 D1  D1 C9  81 E9 ?? ?? 00 00  D1 C1  F7 D1 }
        //$ops_ror2g    = { D1 (C8|C9)  F7 (D0|D1)  D1 (C8|C9) (2D|81 E9) 20 01 00 00 }
        $ops_ror2g    = { D1 C?  F7 D?  D1 C? (2D|81 E9) 20 01 00 00 }
        $ops_ror2s   = { 8A 87 [4]  D1 CB  F7 D3  D1 CB  2B DD  D1 C3  F7 D3 }
        // 308075 (Okt 2017)
        $ops_module_outlook = { 83 C4 FC  6A 00  6A 5E  FF 7? ??  E8 [4]  89 45 FC  83 3D [4] 00  7? ??  C7 05 [4] 00 00 00 00 }

    condition:
        7 of ($str_*)
        or (4 of ($str_*) and any of ($ops_*))
        or 3 of ($ops_*)
}
