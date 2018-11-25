rule win_sedreco_a0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180320"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $ins_block_0 = { b9 1f 00 00 00 2b ce be 01 00 00 00 d3 e6 b9 1f 00 00 00 2b cf bf 01 00 00 00 d3 e7 }
        $string_mutex_0 = "AZZYMutex"
        $string_mutex_1 = "MutYzAz"
       
    condition:
        any of them
}
