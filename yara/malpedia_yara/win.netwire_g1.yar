rule win_netwire_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        kudos = "Jean-Philippe Teissier, Kevin Breen, mak"
        malpedia_version = "20170911"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_I64 = "%d:%I64u:%s%s;"
        $str_f1 = "%s%.2d-%.2d-%.4d"
        $str_f2 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
        $str_f3 = "%.2d/%.2d/%d %.2d:%.2d:%.2d"
        $str_f4 = "%c%.8x%s%s"
        $str_f5 = "0x%.8X (%d)"
        $str_f6 = "0x%.16llX (%I64d)"
        $str_f7 = "%.4d-%.2d-%.2d %.2d:%.2d:%.2d"
    condition:
        5 of ($str_*)
}
