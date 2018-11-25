rule win_formbook_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170815"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
//          $str_Gen0 = { C7 45 ?? ?? 00 ?? 00  C7 45 ?? ?? 00 ?? 00 C7 45 ?? ?? 00 ?? 00 }
//          $str_GenF = { C7 45 ?? FF FF FF ?? 00 ?? 00  C7 45 ?? FF FF FF ?? 00 ?? 00 C7 45 ?? FF FF FF ?? 00 ?? 00 }
//          $reg_Gen0 = /\xC7\x45.[A-Za-z-_\/\\ ]\x00[A-Za-z-_\/\\ ]\x00/
//          $reg_GenF = /\xC7\x85.\xFF\xFF\xFF[A-Za-z-_\/\\ ]\x00[A-Za-z-_\/\\ ]\x00/
 
        $str_Firefox1    = { C7 45 ?? 20 00 46 00 C7 45 ?? 69 00 72 00 C7 45 ?? 65 00 66 00 }
        $str_Firefox2    = { C7 45 ?? 46 00 69 00 C7 45 ?? 72 00 65 00 C7 45 ?? 66 00 6F 00 }
        $str_Thunderbird = { C7 45 ?? 54 00 68 00 C7 45 ?? 75 00 6E 00 C7 45 ?? 64 00 65 00 C7 45 ?? 72 00 62 00 C7 45 ?? 69 00 72 00 C7 45 ?? 64 00 5C 00 }
        $str_Opera1 = { C7 45 ?? 5C 00 4F 00 C7 45 ?? 70 00 65 00 C7 45 ?? 72 00 61 00 }
        $str_Opera2 = { C7 45 ?? 4F 00 70 00 C7 45 ?? 65 00 72 00 C7 45 ?? 61 00 20 00 }

        $op_imul1 = { 0F B6 45 0C  69 C0 01 01 01 01 5? 5? [2-8] C1 (E?|F?) 02 }
        $op_imul2 = { 69 C0 01 01 01 01 5? 5? [2-8] C1 (E?|F?) 02 8? [1-2] F3 AB  8? [1-2] 83 (E?|F?) 03  F3 AA }

    condition:
        2 of ($str_*) 
        or ( any of ($str_*) and any of ($op_*) )
}

