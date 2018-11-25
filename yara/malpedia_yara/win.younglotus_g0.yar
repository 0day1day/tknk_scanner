rule win_younglotus_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180524"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:RED"

    strings:
        $str_dllmaindll = "DllMain.dll"
        $str_pluginme   = "PluginMe"
        $str_openproxy  = "OpenProxy" 
        $str_closeproxy = "CloseProxy"
        $str_sdbak      = "%s\\%d.bak"
        $str_ddddd      = "%4d-%.2d-%.2d %.2d:%.2d"
        $str_dsmhz      = "%d*%sMHz"

    condition:
       5 of them
}

