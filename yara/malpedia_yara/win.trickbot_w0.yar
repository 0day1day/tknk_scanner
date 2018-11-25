rule win_trickbot_w0 {
    meta:
        author = "Marc Salinas @Bondey_m"
        description = "Detects mailsearcher module from Trickbot Trojan"
        reference = "https://www.securityartwork.es/wp-content/uploads/2017/06/Informe_Evoluci%C3%B3n_Trickbot.pdf"
        malpedia_version = "20170613"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $str_mails_01 = "mailsearcher"
        $str_mails_02 = "handler"
        $str_mails_03 = "conf"
        $str_mails_04 = "ctl"
        $str_mails_05 = "SetConf"
        $str_mails_06 = "file"
        $str_mails_07 = "needinfo"
        $str_mails_08 = "mailconf"
    condition:
        all of ($str_mails_*)
}

