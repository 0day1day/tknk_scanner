rule win_reactorbot_a1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "Loader"
        malpedia_version = "20170630"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $str_1      = "PLUGIN" wide
        $op_DGA     = { C7 45 [5] B9 09 00 00 00 BE [4] 8D ?? ?? F3 A5 }
        $op_srand   = { 68 00 00 20 03  8B 4? ??  5?  FF 15 [4] E8 [4]  68 [4]  FF 15 } 
        $op_POST80  = { 83 7D E4 00  7? ??  C7 45 E4 50 00 00 00  8B 45 F8  5?  8B 4D FC  5? FF 15 }  

// shared with reactorbot_dropper
        $str_d_mBD      = "Global\\BD%s%u" wide
        $str_d_1      = "%08X" wide
        //$op_obfs2a  = { 83 C0 01  89 45 FC  8B 4D FC  3B 4D 0C 7? ??  0F B7 55 10 8B 45 FC 8B 4D 08 0F B7 04 41 33 C2 }
        //$op_obfs2b  = { 0F B7 04 41  33 C2  8B 4D FC  8B 55 08  66 89 04 4A  E? ?? }

// shared with reactorbot_banker
        $str_b_priv    = "S:(ML;;NRNWNX;;;LW)" wide
        $str_b_tor    = { 39 30 35 30 00 [0-4] 31 32 37 2E 30 2E 30 2E 31 00 } 
        $str_b_pipe      = "\\\\.\\pipe\\vhost%u" wide
        $str_b_mT      = "Global\\T%s%u" wide
        //$op_pipemut = { 5? 68 [4] 68 03 01 00 00 68 [4] FF 15 [4] 83 C4 10 68 08 02 00 00 }        

    condition:
        1 of ($op_*) and 5 of ($str_*)
}

