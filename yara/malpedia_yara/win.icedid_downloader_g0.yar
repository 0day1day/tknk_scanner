rule win_icedid_downloader_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171123"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_a = "Add" wide fullword
        $str_b = "Force" wide fullword
        $str_c = "GET" wide fullword
        $str_e = "exe" wide fullword
        $str_f = "/e=" wide fullword

        $ops_rc4 = { 8B 7D 08  83 C7 0A  83 EE 0A  8B DF  EB 02  47  4E  80 3F 00 } 
        $ops_obf = { C1 E8 03  8B 4? ??  C1 E1 1D  0B C1  89 4? ??  0F B7 4? ??  03 4? ?? }  

    condition:
        all of ($str_*) 
        or (3 of ($str_*) and 1 of ($ops_*))
        or (2 of ($ops_*)) 
}
