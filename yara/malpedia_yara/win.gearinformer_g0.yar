rule win_gearinformer_g0 {
    meta:
        author = "Various authors / Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171121"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $gear_DInformer = "Gear.Informer"
        $gear_SInformer = "Gear Informer"
        $gear_Unformer  = "Gear_Informer"
        $gear_Informer  = "GearInformer"
        $gear_Log1          = "{0} Log - {1}\\{2}"
        $gear_Log2          = "{0}{2}\\{3}{0}{0}{4}"

        // shared with hawkeye reborn
        $str_Botkiller     = "_BotKiller"
        $str_AVkiller      = "_AntiVirusKiller"
        $str_Cloud1  = "_CloudURL"
        $str_Cloud2  = "_CloudKey"
        $str_Cloud3  = "_CloudToken"
        $str_Panel1  = "_PanelURL"
        $str_Panel2  = "_PanelSecret"
        $str_Log1    = "_KeyboardLogger"
        $str_Log2    = "_ClipboardLogger"
        $str_Log3    = "_ScreenshotLogger"
        $str_Log4    = "_WebcamLogger"
        $str_Log5    = "_PasswordLogger"
        $str_Log6    = "_CookieLogger"

        // shared with ispy keylogger
        $str_rva     = "5D38EBE25C05C7DB92A7003B08B1539A2E1E0406"

    condition:
        1 of ($gear_*) and 1 of ($str_*)
}
