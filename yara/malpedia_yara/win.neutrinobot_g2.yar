rule win_neutrinobot_g2 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180911"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_trigger    = "Cannot put trigger ID: %x"
        $str_lsls       = "%ls%ls" wide
        $str_stack_lsls = { 6A 25 5?  6A 6C 66 89 45 F0 5?  6A 73 66 89 45 F2 5?  6A 5C 66 89 45 F4 5?  6A 25 66 89 45 F6 5?  6A 6C 66 89 45 F8 5?  66 89 45 FA  6A 73 }

        $op_deobf_a = { 7? ?? 0F [3] 33 ?? 69 ( C? | D? ) 93 01 00 01 [0-1] 4? E? }
        $op_deobf_ax = { 7? ?? 0F [3] 33 ?? 69 ( C? | D? ) [4] [0-1] 4? E? }
        $op_deobf_b = { 33 (C? | D? ) 8D [2] 66 83 ?? ?? 4? 8? (E? | F?) B4 00 00 00 76 ?? }
        $op_deobf_bx = { 33 (C? | D? ) 8D [2] 66 83 ?? ?? 4? 8? (E? | F?) [4] 76 ?? }

        $op_decrypt0a = { 59 59  33 C9  [0-1] 83 34 48 ??  41  3B 4D 0C  76 F?  5D  C3 }
        $op_decrypt0b = { FF 75 0C  FF 75 08  E8 [4] 59 59  (89 45 FC  83 65 F8 00 EB 07 | 33 C9 80 34 01 07 41) }
        $op_decrypt1 = { 59 59  33 C9  80 34 01 ??     41  3B 4D 0C  76 F6  5D  C3 }
        $op_decrypt2 = { 0F B? 0? [0-1]  33 (D8|45 FC) [0-6] 69 ?? 93 01 00 01 }

        $op_mutex_v3a = { 68 A1 E8 6E 49 5?       E8 [4] 59 59 }
        $op_mutex_v3b = { 68 A1 E8 6E 49 [1-6] 5? E8 [4] 59 59 }
        $op_mutex_v3c = { 68 A1 E8 6E 49 5? [1-3] E8 [4] 59 59 }
        $op_mutex_v3d = { 68 A1 E8 6E 49 [1-6] 5? [1-3] E8 [4] 59 59 }

        // shared with bot
        //$op_decode_ROL_5_2      = { EB 0E  0F B7 C9  C1 C0 07  33 C1  83 C2 02  0F B7 0A  66 85 C9  75 }

    condition:
        $str_trigger or
        3 of them
}
