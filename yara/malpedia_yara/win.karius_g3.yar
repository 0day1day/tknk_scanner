rule win_karius_g3 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "config module"
        malpedia_version = "20180614"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_static1 = "\"action\"" 
        $str_static2 = "\"integrity\"" 
        $str_static3 = "\"admin\"" 
        $str_static4 = "\"group\"" 

    condition:
        4 of them
}
