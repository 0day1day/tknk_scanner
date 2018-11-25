rule win_advisorsbot_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>, Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180509,20181005"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $op32_start  = { 55 8b ec 83 e4 f8 51 56 8b 30 33 d2 }
        $op64_xorA   = { 33 D2   F7 F1  41 8B C0  83 E2 10  81 [2-5]  8D ?A [1-4]  D3 E0 44 33 C0 }
        $op64_xorB   = { B8 [4]  F7 E1  41 8B C0  C1 EA (0?|1?)                 8D ?A [1-4]  D3 E0 }

    condition:
        1 of them
}
