rule win_unidentified_046_a0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        description = "Unknown x64"
        malpedia_version = "20180613"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"
    strings:
        $binary_0 = { 49 83 e9 02 49 8b c2 49 f7 e0 48 c1 ea 03 }
        
    condition:
        all of them
}
