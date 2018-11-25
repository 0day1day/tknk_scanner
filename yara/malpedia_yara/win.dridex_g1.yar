rule win_dridex_g1 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        description = "Unpacked Dridex v4 x64"
        malpedia_version = "20180606"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $dridex64_0 = { ff c7 8d 48 e0 83 f8 61 0f 42 c8 41 8b c6 }
        $dridex64_1 = { 48 8d 4a 01 41 ff c1 8a 01 41 2a c0 3c 07 }
        
    condition:
        all of them
}
