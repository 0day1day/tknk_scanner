rule win_eredel_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180919"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_unique_v   = "EREDEL STEALER EXTENDED" wide ascii
        $str_eredel     = "Eredel" wide ascii
        $str_eredel_log = "errorEredel.log" wide ascii
        $str_Telegram   = "Telegram Stealer" wide ascii
        $str_cc         = "credit_cards" wide ascii
        $str_hwid       = "hwid={0}" wide ascii
        $str_telegram   = "&telegram={0}" wide ascii

    condition:
        4 of them
}
