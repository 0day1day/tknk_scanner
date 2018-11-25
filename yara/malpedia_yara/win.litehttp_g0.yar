rule win_litehttp_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180926"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_com_os = "&os=" wide ascii
        $str_com_pv = "&pv=" wide ascii
        $str_newtask= "newtask" wide ascii
        $str_hours  = "hour(s) ago" wide ascii
        $str_ping   = "/C ping 1.1.1.1 -n 1 -w 4000" wide ascii
        $str_black  = "Blackshades NET" wide ascii
        $str_lite   = "LiteHTTP" wide ascii
        $str_UA     = "E9BC3BD76216AFA560BFB5ACAF5731A3"

    condition:
        5 of them
}
