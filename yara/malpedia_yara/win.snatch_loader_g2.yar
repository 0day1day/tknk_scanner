rule win_snatch_loader_g2 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171107"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        // 201701
        $str_o_test = "test arguments"
        $str_o_task = "</TASK>"
        $str_o_data = "DATA_SUCCESS|"
        $str_o_inject0 = "--START INJECT--"
        $str_o_inject1 = "--DONE INJECTION--"

        // 201708
        $str_form_1 = "%08X%X%X%X%08X%X"
        $str_conf_1 = "</TIME>"
        $str_conf_2 = "</NAME>"
        $str_conf_3 = "</CFG>"
        $str_conf_4 = "</KEY>"
        $str_conf_5 = "</SRV>"

        $str_comm_1 = "&cmpn="
        $str_comm_2 = "&prcl="
        $str_comm_3 = "&win=%d&x64=%d&adm=%d"
        $str_comm_4 = "&sftl="
        $str_comm_5 = "&usrn="
        $str_comm_6 = "&uagn="
        $str_comm_7 = "&trash="
        $str_comm_8 = "&result="
        $str_comm_9 = "&guid=%08X%08X&name="

        $op_crypt1          = { C1 C? 08  0F B? C0  33 ?0  4?  8A 0?  84 C0  7?  }
        $op_crypt2          = { C1 C? 08  8D 43 BF  3C 19  77 03  80 C3 20  0F B6 C3  83 C1 02 }
        $op_crypt3          = { 0F BE 02  8D 52 02  C1 C7 08  33 F8  83 E9 01 7?  }

    condition:
        4 of ($str_o_*)
        or 6 of ($str_*)
        or ( 4 of ($str_*) and any of ($op_*) )
}
