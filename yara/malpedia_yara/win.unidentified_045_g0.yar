rule win_unidentified_045_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        description = "Unknown 045"
        malpedia_version = "20180613"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $string_0 = "%s%.8X.exe"
        $string_1 = "http://%s:%d/%s/%s"
        
    condition:
        all of them
}
