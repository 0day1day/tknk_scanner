rule win_morphine_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170821"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_morphine = "Status: morphinE" wide

        $str_mutex = "02202MTX1" 
        $str_dflt   = "#DFLT-ID#"
        $str_dflt2   = "#DFLT-ID2#"
        $str_dtmp   = "dtmp1.tmp"
        $str_data   = "data.dbb"
        $str_ozn    = "ozn055"

        $str_v4_s = "%s|%s@%s|%s|%s|%s|%s|"

        $op_getVersion = {  B9 06 00 00 00  B8 [4]  E8 [4]  33 C0 5A 59 59  64 89 10 }

    condition:
        $str_morphine 
        or 3 of ($str_*) 
        or ( any of ($str_*) and any of ($op_*) )
}

