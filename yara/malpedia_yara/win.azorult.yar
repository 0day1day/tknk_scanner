rule win_azorult_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170814"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_A_getconfig = "getconfig"
        $str_A_sendreport = "sendreport"
        //$str_A_NOWORKEXIT = "_NO_WORK_EXIT_"
        $str_A_Passwords = "\\Passwords.txt" wide
        $str_A_Programms = "\\Programms.txt" wide
        $str_A_Process = "\\Process.txt" wide
        //$str_A_Info = "\\Info.txt" wide
        $str_B_getcfg = "getcfg="
        $str_B_reportdata = "reportdata="
        $str_B_Passwords = "Passwords.txt"
        $str_B_CookieList = "CookieList.txt"
        $str_B_SYSInfo = "SYSInfo.txt"
        
        $op_hostconnect = { 8B 00  8B 00  89 [5]  6A 50  FF [2-5]  66 89 85 ?? ?? FF FF  6A 10 }

    condition:
        all of ($str_A_*) or all of ($str_B_*) or
        ( 2 of ($str_*) and any of ($op_*) ) 
}

