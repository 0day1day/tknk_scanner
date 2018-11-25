rule win_qakbot_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170609"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $loader_1 = "%s.%06d"
        $loader_2 = "2%s%u"
        $loader_3 = "%s\\%d.exe"
        $pipe = "\\\\.\\pipe\\%ssp"
        $data_end = "data_end"
        $data_inject = "data_inject"
        $data_after = "data_after"
        $data_before = "data_before"

        $rc4_0 = { 0F B6 ??  8A 14 ?? [7-11] 99  F7 7D 0C  4?  FF 4D FC  75 C? }
        $rc4_1 = { 81 E? FF 00 00 80 79 08  4?  81 C? 00 FF FF FF  4?  0F B6 }

        $crypt_N = { 57 56 E8 [4] 8D 45 EC  [0-1]  83 C7 EC  8D 5E 14  [0-1]   57 53 E8 [4] 6A 14 }

        $dga_opN = { BE [4-7]        8D 7D E4  [0-3]     F3 A5 [0-3]    66 A5 [0-3]           A4  E8 }

    condition:
        ( (any of ($rc4_*)) or (any of ($crypt_*)) or (any of ($dga_*)) ) and ((2 of ($loader_*)) or $pipe or (all of ($data_*)))
}
