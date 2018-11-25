rule win_snatch_loader_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171107"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        // 201708
        $op_caller     = { A1 [4]  85 C0  75 ??  6A ??  59  E8 [4]  BA [4]  8B C8  E8 [4]  A3 } 

        $op_crypt1          = { C1 C? 08  0F B? C0  33 ?0  4?  8A 0?  84 C0  7?  }
        $op_crypt2          = { C1 C? 08  8D 43 BF  3C 19  77 03  80 C3 20  0F B6 C3  83 C1 02 }
        $op_crypt3          = { 0F BE 02  8D 52 02  C1 C7 08  33 F8  83 E9 01 7?  }

        $op_loader          = { 49  83 F9 (0?|1?)  0F 8? [2] 00 00  FF 24 8? [4]  8B 35 [4]  85 F6  0F 8? [2] 00 00  B9 }

    condition:
        3 of them
}
