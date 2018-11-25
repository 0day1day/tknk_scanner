rule win_gootkit_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171201"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        ///////
        // dll loader (stage2)
        ///////

        // 201609 (obf)
        $ops_memsetcpy = { 32 C? B? ?? ?? 00 00  [0-6]  F3 AA  [0-10]   BE [4] (B? ?? ?? 00 00 F3 A4 | F3 A4) }
        $ops_deobf1    = { 8B C3               8D 0C 33  99  F7 (7D ?? |BD [3] ??) 8A 44 1? ??  8B 55 ??  32 04 0A  88 01  43 }
        $ops_deobf2    = { 8B C?  C7 85 [4-8]  99  8D 0C 3?  F7 (7D ?? |BD [3] ??) 8A 44 1? ??            32 04 0?  4?  88 01 }

        // 2015
        // loader binaryImage: RegOpen, RegQuery (binaryImage)
        $ops_loader_binaryImage = { 50 33 C0 50 50 50 FF 7? ?? FF 7? ?? FF ?? ?? 85 C0 75 ?? 39 4? ?? 74 ?? }

        // 201605
        $ops_decrypt = { 32 C1 [2-4] ?? ?? 00 00 8? [3] 8B ?? 99 4? F7 }


        // 2015
        $str_K1 = "vendor_id"
        $str_K2 = "mainprocessoverride"
        $str_K3 = "--no-malware-thanks"
        $str_K4 = "type=renderer"
        // 201601
        $str_K5 = "unstable_%d"
        $str_K6 = "/rpersist2/%d"
        // 201605
        $str_K7 = "%d:%s Ignition...."
        // 201609
        $str_K8 = "servicedll_%d"
        $str_K9 = "/rpersist3/%d"
        $str_K10 = "standalonemtm"
        // 201611
        $str_K11 = "scheduler_%d"

        // 2016
        $str_R0 = "binaryImage%d" wide

        // 201505
        $str_js0 = "zlib" fullword
        $str_js1 = "spyware" fullword
        $str_js2 = "line_reader" fullword
        $str_js3 = "tunnel" fullword
        $str_js4 = "client_proto_spyware" fullword
        $str_js5 = "clienthttp" fullword

        // 201605
        $js_BOT0 = "BOT_MACHINE_UUID"
        $js_BOT1 = "BOT_USER"
        $js_BOT2 = "BOT_COMPUTERNAME"
        $js_BOT3 = "BOT_VERSION"
        $js_BOT4 = "BOT_PROCESS"
        $js_BOT5 = "BOT_RANDOM"

        $js_config0 = "RegistryPath ="
        $js_config1 = "RegistryHive ="
        $js_config2 = "SpConfigKey ="

        $js_zeusmask = "zeusmask"
        $js_zeusfunc = "zeusfunctions"

    condition:
        2 of ($ops_*)
        or 1 of ($str_R*)
        or 4 of ($str_K*)
        or 5 of ($js_*)
        or (any of ($ops_*) and any of ($str_*))
}
