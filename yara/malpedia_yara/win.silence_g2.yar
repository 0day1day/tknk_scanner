rule win_silence_g2 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "Targets the .NET version for proxy of win.silence"
        malpedia_version = "20180926"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_p0       = "|{0}|" wide
        $str_connect  = "connectTo" wide
        $str_connect0 = "CONNECT {0} HTTP/1.1" wide
        $str_kgs      = "KGS!@#$%" wide

    condition:
        3 of them
}
