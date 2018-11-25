rule win_darksky_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180327"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darksky"
    strings:
        $activation     = "activation.php?key=" wide ascii nocase
        $asctivation_64 = "2f61637469766174696f6e2e7068703f6b65793d"
        $key_def        = "key=fSJ" wide ascii nocase
        $str_version_r  = "\"noisrev\""
        $str_username_r = "\"emaNresU\""
        $str_admin_r    = "\"nimdA\""

        $str_win        = "\",\"win\":\""
        $str_win_s      = "\", \"win\":\""
        $str_admin      = "\",\"Admin\":\""
        $str_admin_s    = "\", \"Admin\":\""
        $str_username   = "\",\"UserName\":\""
        $str_username_s = "\", \"UserName\":\""
        $str_http       = "\",\"http\":\""
        $str_http_s     = "\", \"http\":\""
        $str_ram       = "\",\"ram\":\""
        $str_ram_s     = "\", \"ram\":\""
        // GalaxyLoader
        $str_hwid       = "\",\"hwid\":\""

        $set_process    = "Set Process="
        $set_old        = "Set Oldprocess="
        $service        = "\" -service"

        $str_version_64 = "dmVyc2lvbgo" wide ascii nocase
        $str_version    = /\x00\x00\d\.\d\.\d\x00\x00/
        // movVersion xor xor call call cmp
        $op_version     = { B9 [4]  33 ?? 33 ??  E8 [4]  E8 [4]  3D B7 00 00 00  7? ??  6A 00  E8 }

        $op_useragent   = { E8 [4]  B8 [4]  B9 0F 00 00 00  8B 15 [4]  E8 }
    condition:
        4 of them
}
