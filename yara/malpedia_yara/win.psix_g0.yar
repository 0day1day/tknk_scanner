rule win_psix_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        kudos = "James_inthe_Box / Jason Reaves"
        malpedia_version = "20180917"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_psix    = "PsiXMainModule" wide ascii
        $str_checkin = "/curl.php?token=" wide
        $str_command = "action=command&bot_id=" wide
        $str_result  = "action=result&command_id" wide
        $str_bot     = "BotModules" wide ascii
        $str_complex = "ComplexModule" wide ascii

    condition:
        3 of them 
}
