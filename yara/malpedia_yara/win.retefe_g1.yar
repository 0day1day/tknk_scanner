rule win_retefe_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        comment = "Retefe v5 unpacks javascript in memory"
        malpedia_version = "20171103"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $v5_ops_CoCLSID_JScriptWScipt = { 4A 00 53 00 63 00 72 00 69 00 70 00 74 00 00 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 00 00 }
        $v5_ops_CoInitializeEx = { 6A 00  C7 43 0? 01 00 00 00  FF 15 [4]  C7 45 (E?|F?) [4]  33 C9  C7 45 (E?|F?) [4]   8D 41 ??  30 44 0? ??  41 } 
        $v5_ops_CLSIDFromProgID = { 33 C9  8B C7  F7 E2  0F 90 C1  F7 D9  0B C8  51  E8 }
        $v5_ops_CPUID = { (81 F1|35) [4]  8B 45 ??  (81 F1|35) [4]  0B C8  8B 45 ??  6A 01  (81 F1|35) [4]  0B C8  5?  6A 00  5? 5?  0F A2 }
        $v5_ops_deobf_javascript = { 8B CE  E8 [4]  0F AF C6  BB FF FF FF 7F  6A 01  C1 E0 03  2B D8 E8 } 
    condition:
        2 of ($v5_ops*)
}

