rule win_arkei_stealer_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20181004"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_arkei    = "Arkei Stealer"
        $str_barkei   = "\\Arkei"
        $str_parkei   = "Bot\\trunk\\Release\\Arkei.pdb"
        $str_dev      = "Develop by Foxovsky"
        $str_crack    = "Crack by Xak"
        $str_screen   = "files\\screenshot.bmp"
        $str_info     = "files\\information.log"
        $str1         = "server/grubConfig"
        $str2         = "server/gate"
        $str3         = "server/checkingLicense"
        $str_ArkeiLic = "Arkei/1.0 CheckingLicense"
        $str_Install  = "[Installed Software]"
        $str_Process  = "[System Processes]"

    condition:
       4 of them
}
