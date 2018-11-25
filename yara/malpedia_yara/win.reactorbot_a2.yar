rule win_reactorbot_a2 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "banker"
        malpedia_version = "20170630"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $str_pip2    = "\\\\.\\pipe\\log%s%u" wide
        $str_mV      = "Global\\V%s%u"  wide
        $str_mS      = "Global\\S%s%u"  wide
        $str_c1      = "set_url"
        $str_c2      = "data_before"
        $str_c3      = "data_after"
        $str_c4      = "data_end"
        $str_c5      = "data_inject"
        $op_ports    = { B9 FF 7F 00 00  66 89 4D FC  EB 0C  66 [3] 66 [3] 66 [3] 0F B7 45 FC  3D FE FF 00 00 }
        $op_hashes  = { 04 00 00 00  C1 E2 00  8? [4-6]  A3 [4]  C? [4-8]  C? [4-10]  B? 04 00 00 00  6B C9 00 }

// shared with reactorbot_loader
        $str_b_priv    = "S:(ML;;NRNWNX;;;LW)" wide
        $str_b_tor    = { 39 30 35 30 00 [0-4] 31 32 37 2E 30 2E 30 2E 31 00 } 
        $str_b_pipe      = "\\\\.\\pipe\\vhost%u" wide
        $str_b_mT      = "Global\\T%s%u" wide
        //$op_pipemut = { 5? 68 [4] 68 03 01 00 00 68 [4] FF 15 [4] 83 C4 10 68 08 02 00 00 }        

    condition:
        1 of ($op_*) and 6 of ($str_*)
}

