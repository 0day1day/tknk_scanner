rule win_seduploader_a0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $code_with_constants_0 = { 81 (fe | ff) c8 00 00 00 74 ?? 81 ( fe | ff ) 94 01 00 00 75 }
        $code_with_constants_1 = { 51 6a 03 6a 06 b3 09 e8 }
        $code_with_constants_2 = { ba 42 20 00 00 66 33 55 fc 66 d1 ea }
        $code_xor_const = { 35 56 d7 a7 0a }

    condition:
        any of ($code_*)
}
