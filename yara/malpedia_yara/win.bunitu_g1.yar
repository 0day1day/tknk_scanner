rule win_bunitu_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        reference = "https://blog.malwarebytes.com/threat-analysis/2015/07/revisiting-the-bunitu-trojan/"
        malpedia_version = "20171005"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $op_setup    = { E8 [4]  0B C0  7C ??  66 3D 00 20  7D ??  6A 05 }
        $op_callcmd1 = { 8D 05 [4]  C7 00 3C 00 00 00  C7 40 04 40 00 00 00  8B 0D [4]                                           C7 40 }
        $op_callcmd2 = { 8D 05 [4]  C7 00 3C 00 00 00  C7 40 04 40 00 00 00  FF 04 24   (C7|36 C7) 05 [8]  (C6|36 C6) 05 [4] 73  C7 40 }
        $op_version  = { BA 01 00 00 00  4A  6A 7E  68 [4] 68 [4]  68 [4] 52 68 00 08 00 00 E8 }
        $op_keygen   = { BF [4]  0F 31  C1 C0 03  50  48  8F 07  C1 C0 02  40 50 8F 47 04 D1 C0 }

    condition:
       2 of them
}

