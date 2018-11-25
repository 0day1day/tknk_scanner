rule win_smokeloader_g2 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "2012 version"
        comment = "works on memdumps only"
        malpedia_version = "20141101"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $str_cmd = "cmd=getload&login="
        $str_run = "&run=ok\x00"
//        $str_file = "&file=\x00"
//        $str_sel = "&sel=\x00"
//        $str_UA = "User-Agent: Mozilla/4.0\x0d\x0a"

    condition:
        1 of them
}
