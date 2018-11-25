rule win_xtunnel_a0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180313"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $crypto_keys_dword_0 = { 98 7A B9 99 }
        $crypto_keys_dword_1 = { 8B 23 6C 89 }
        $crypto_keys_dword_2 = { E4 7B 7F 11 }

        $crypto_keys_byte_0 = { 98 [6] 7A [6] B9 [6] 99 }
        $crypto_keys_byte_1 = { 8B [6] 23 [6] 6C [6] 89 }
        $crypto_keys_byte_2 = { E4 [6] 7B [6] 7F [6] 11 }

    condition:
        all of ($crypto_keys_dword_*) or all of ($crypto_keys_byte_*)
}
