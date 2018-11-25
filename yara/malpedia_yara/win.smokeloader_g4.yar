rule win_smokeloader_g4 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "2017 version"
        comment = "seems to works on memdumps only"
        malpedia_version = "20180115"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $op_17_xorrol        = { 32 28  C1 C1 08  32 CD  D1 E1 40  80 38 00  7? ?? }

        // $op_17_create_beacon = { 3D B7 00 00 00 7? ?? 8D 45 FC  5? 5? 6A 0D 68 11 27 00 00 E8 [4] 5? 33 C0 }
        $op_17_create_beacon = { 3D B7 00 00 00  7? ??  8D 4? [1-2]  5? 5? [0-1]  6A 0D  [0-5]  ?? 11 27 00 00 }
        $op_17_create_step_1 = { 8D 45 0C  5? 5? FF 75 FC 3? ??  68 12 27 00 00  FF 75 08 E8  }
        $op_17_create_step_2 = { 8D 4? [1-5]  5? 5?   6A 72  ?? 12 27 00 00  }
        $op_17_create_step_3 = { 5?  8D [2-3]  C7 4? [1-2] 7C 3A 7C 00 [0-2]  E8 [4] [0-7]  83 F8 FF  }

        $op_17_get_rc4key_1  = { 5? 5? FF 75 0C  C7 45 FC [4]  E8 [4]      FF 75 0C  [0-4]  FF 75 08  5?  FF 15 [4] 6A 04 }
        $op_17_get_rc4key_2  = { 5? 5?  8B DA  C7 45 FC [4]  8B ?? 8B ?? 5?  E8   }
        //$op_17_conc          = { 50 E8 [4] 8? ??   B8 E1 07 00 00   66 8? ??       68 [4]  8D 4? ??  50  FF 15 [4]  68 }
        $op_17_conc          = {    E8 [4] 8B F?   B8 E1 07 00 (00 66 8? ?? | 00)  68 [4]  8D 4? ??  (66 89 ?? 5? | 5?)  FF 15 [4]  68 }

    condition:
        2 of them
}
