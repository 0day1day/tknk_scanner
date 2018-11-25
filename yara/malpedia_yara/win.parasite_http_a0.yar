rule win_parasite_http_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        contribution = "hexlax"
        malpedia_version = "20181031"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.parasite_http"
    strings:
        // plugins
        $str_parasite   = "Parasite HTTP"
        $str_pluginbase = "PluginBase.pdb"
        $str_ftp        = "PluginFTPRecovery"
        $str_im         = "PluginIMRecovery"
        $str_password   = "PluginPasswordRecovery"
        $str_proxy      = "PluginReverseProxy"
        $str_windows    = "PluginWindowsRecovery"
        $str_hvnc_tiny  = "HELLO_PARASITE"
        $str_data       = "data="
        $str_lll        = "_LLL@"

        // main
        $op_break       = { 83 E1 55  F7 D0  F7 D1  83 E0 AA  F7 D0  23 C1  3D 99 00 00 00 }
        $op_rc4         = { 6A 42  59  A3 [4] E8 [4]  6A 42  59  A3 [4] E8 [4] 6A 42  59  A3 [4] E8 [4] A3 }
        $op_ticks       = { 2B 5D FC  81 FB D0 07 00 00  77 0C  81 FB 84 03 00 00  7?}

    condition:
        3 of ($str_*) or
        2 of ($op_*)
}
