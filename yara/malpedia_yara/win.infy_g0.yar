rule win_infy_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        date = "2017-08-04"
        malpedia_version = "20170804"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $s0 = "ZipForge1"
        $s1 = "INFY"
        $s2 = "infy"
        $s3 = "After_5_Minate_Procedure" wide

    condition:
        all of them
}
