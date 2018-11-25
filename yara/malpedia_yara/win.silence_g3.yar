rule win_silence_g3 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "Targets the main module of win.silence"
        malpedia_version = "20180926"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_monitor       = " monitor" wide
        $str_bxy           = "&bxy=" wide
        $str_uniq1         = "htrjyytrn" wide
        $str_uniq2         = "htcnfhn" wide
        $str_uniq3         = "ytnpflfybq" wide
        $op_c21            = { 5?  8B 0?  68 [4]  68 [4]  FF ??  84 C0  75 ?? }
        $op_c22            = { 56  52  68 [4]  FF ??  84 C0  74 ??  8D }

    condition:
        3 of them
}
