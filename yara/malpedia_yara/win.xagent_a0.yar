rule win_xagent_a0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180313"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $crypto_block_32bit_0 = { 66 8b 5d fc 66 d1 eb 66 33 d9 0f b7 db }
        $crypto_block_32bit_1 = { d0 e8 8a d8 32 5d fc f6 c3 01 }
        $crypto_block_64bit_0 = { 0f b6 c2 32 c1 66 d1 e9 a8 01 74 }
        $crypto_block_64bit_1 = { 66 41 33 cb d0 ea 49 ff }
       
    condition:
        all of ($crypto_block_32bit_*) or all of ($crypto_block_64bit_*)
}
