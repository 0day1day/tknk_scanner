rule win_karius_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "injector module"
        malpedia_version = "20180614"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_exe32    = "injector32.exe"
        $str_exe64    = "injector64.exe"
        $str_refl     = "ReflectiveLoader"
        $str_AP32     = "AP32\x18\x00"
        $str_url      = "\"url\":"
        $str_key      = "\"key\":"
        $str_time     = "\"time\":"
        
        $str_fs_sddd  = "%s %04d sp%1d.%1d %s"
        $str_register = "register" fullword
        $str_commands = "commands" fullword

    condition:
        4 of them
}
