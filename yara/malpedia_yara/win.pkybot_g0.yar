rule win_pkybot_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170412,20180215"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_xml      = "xml version=\"1.0\" encoding=\"UTF-8\""
        $str_qampapos = "\x00amp\x00apos\x00"
        $str_ampquot  = "\x00amp\x00quot\x00"
        $op_1080      = { 74 3?  8D ?? FF FE FE FE  F7 D?  23 ??  [1-2] 80 80 80 80 7? ?? }
        $op_dec       = { 6A 01  8D 4? ??  [0-4]  5?  8B 45 0C  [0-4]  48 50  [0-8]    E8 [4] 83 C4 14 }

        // until end 2017, but fp due to rc6 variant (eg hawkeye keylogger lib)
        // $op_rc6_math = { C1 E2 10 25 00 FF 00 00 0B C2 8B D1 81 E2 00 00 FF 00 C1 E9 10 }
        // also in gozi
        $op_math1     = { 75 0?  0F B6 0?  81 C? 00 01 00 00  [0-3] 4?  F6 [1-2] 01  0F 84 }

    condition:
        1 of ($str_*) and 1 of ($op_*)
}
