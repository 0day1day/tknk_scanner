rule win_neutrino_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        version = "20170710,20180911"
        malpedia_version = "20180911"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_reg_date = "%02d.%02d.%04d" wide
        $str_acs = " /a /c %s" wide
        $str_sss = "%s %s" wide
        $str_lssls = "%ls %ls" wide
        $str_lsdls = "%ls.%ls" wide
        $str_lsuls = "%ls_%ls" wide
        $str_cc = "--->"
        $str_co = "<!---"
        $str_ff = "100101 Firefox/38.0"
        $str_d = "%[^:]:%d" wide

        $str_v2_v3_d = "%02d.%02d.%d %02d:%02d ]" wide
        $str_v2_v3_s_i_d_s = "%s\\%i_%d.%s" wide
        $str_v2_v3_stxt = "%s\\%s\\logs\\%s%s.txt"
        $str_v2_v3_getcmd = "getcmd=1&uid=%s"
        $str_v2_v3_osav = "&os=%s&av=%s&"
        $str_v2_v3_version = "&version=%s&"
        $str_v2_v3_serial = "&serial=%s&"
        $str_v2_v3_quality = "&quality=%i&"
        $str_v2_v3_ua = "Neutrino/2.1"

        $str_comm1 = "enter" wide fullword
        $str_comm2 = "success" fullword


        $un_v2_cmduid = "cmd=1&uid=%s&cn=%s&os=%s&av=%s&"
        $un_v2_cmduidw = "cmd=1&uid=%s&cn=%s&os=%s&av=%s&" wide
        $un_v2_taskexec = "%s?taskexec=1&task_id=%s"
        $un_v2_taskexecw = "%s?taskexec=1&task_id=%s" wide
        $un_v2_taskfail = "%s?taskfail=1&task_id=%"
        $un_v2_taskfailw = "%s?taskfail=1&task_id=%" wide


        $un_v3_admin = "21232f297a57a5a743894a0e4a801fc3"

        $un_v3_cmduid = "cmd=1&uid=%s&os=%s&av=%s&"
        $un_v3_cmuidw = "cmd=1&uid=%s&os=%s&av=%s&" wide


        $un_v4_v5_justforfun = "bc00595440e801f8a5d2a2ad13b9791b"

        $un_v4_cmdid = "cmd=1&id=%ls&name=%ls&os=%ls&p=%i&av=%ls&v=%ls&w=%i"
        $un_v4_cmdidw = "cmd=1&id=%ls&name=%ls&os=%ls&p=%i&av=%ls&v=%ls&w=%i" wide
        $un_v4_plugin = "plugin=1&desc=%s&id=%ls&name=%ls&text=%s"
        $un_v4_pluginw = "plugin=1&desc=%s&id=%ls&name=%ls&text=%s" wide
        $un_v4_ffid = "ff=1&id=%ls&name=%ls&host=%s&form=%s&browser=%i"
        $un_v4_ffidw = "ff=1&id=%ls&name=%ls&host=%s&form=%s&browser=%i" wide

        $un_v5_cmdls = "cmd&%ls&%ls&%i&%i&%i&%i&%i&%ls&%s&%ls&%ls"
        $un_v5_cmdls_w = "cmd&%ls&%ls&%i&%i&%i&%i&%i&%ls&%s&%ls&%ls" wide


        $op_decode_urls0        = { C1 E? 07  8B 4D F8  C1 E9 19  0B C1  89 45 F8  8B 55 FC  0F B7 02 }
        $op_decode_urls_gen     = { C1 E? 04  [0-6]  03 ?1  [0-6]    83 C2 02  [0-6]  (81 E1|25) 00 00 00 F0  [0-3]   7? ??  [2-3]  C1 E? 18  33 }
        $op_decode_enter        = { 8D 45 ?? 50 6A 00 68 [4]  FF 75 ??  E8 [4] 83 C4 10 89 45 ?? [0-3] E8 }
        $op_wait                = { 68 ?? ?? 00 00  [2-10]   3D 02 01 00 00  75 0D  81 7D ?? 03 01 00 00 75 04 C6 45 ?? 01 }

        $op_decode_ROL_5_2      = { EB 0E  0F B7 C9  C1 C0 07  33 C1  83 C2 02  0F B7 0A  66 85 C9  75}
        $op_loadlibrary_5_2     = { 56 57 BE [4] 8D [2-5] A5 A5 (A5 | 66 A5 ) A4 BE [4] 8D [2-5] A5 A5 }

        $op_botnet_version_5_2  = { 68 00 10 00  (00|00 89 ?? ??)  E8 [4]  8B 7? ??  83 C4 ??  68 [4]  [3-8] 5? 68 }
        $op_botnet_version_5_3a = { 05 08 02 00 00  5? E8 [4]  5? 89 ?? ?? 68 [4]  A1 [4]  FF [5] 68 }
        $op_botnet_version_5_3b = { 5? 5? 89 ?? ??  83 ?? ?? 00  0F [5]  68 [4]  A1 [4] FF [5] 68 }
        $op_botnet_version_5_x  = {       89 ?? ??  83 ?? ?? 00  0F [5]  68 [4]  (A1|8B|FF) [4-5] (A1|8B|FF) [4-5] [0-1] 68 }

    condition:
        ( 2 of ($op_*) and 3 of ($str_*) ) or
        ( 7 of ($str_*) ) or
        ( 2 of ($un_*) )
}
