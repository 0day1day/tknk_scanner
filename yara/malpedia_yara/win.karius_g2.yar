rule win_karius_g2 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "banker module"
        malpedia_version = "20180614"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_dll32   = "mod32.dll"
        $str_dll64   = "mod64.dll"
        $str_refl    = "ReflectiveLoader"
        $str_create  = "<#CREATE"
        $str_date    = "<#DATE"
        $str_show    = "<#SHOW"
        $str_botid   = "<#BOTID"
        $str_injects1 = "\"webinjects\":"
        $str_injects2 = "\"host\":"
        $str_injects3 = "\"path\":"
        $str_injects4 = "%IDBOT%"

    condition:
        4 of them
}
