rule win_coreshell_a0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180320"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $jmp_coreshell = { 55 68 01 00 00 00 68 00 00 00 00 e8 0a 00 00 00 63 6F 72 65 73 68 65 6C 6C 00 }
        $ins_seq_0 = { 8b c7 83 c6 0c 24 0f 8b cf f6 d8 1b c0 }
        $ins_seq_1 = { 8a d8 02 db 02 db 02 db 88 5d 0f }
        $ins_seq_2 = { 8d 46 01 8a d9 83 e0 07 02 da }
        $ins_seq_3 = { f7 fe 29 d1 21 ca 0f af d1 }
        $ins_seq_mmx = { 0f 6e 45 e0 0f 72 f0 02 0f 7e 45 e0 }
        $string_id_path = "% s   I D : % d   P a t h :" wide
        
    condition:
        any of them
}
