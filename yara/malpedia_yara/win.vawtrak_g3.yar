rule win_vawtrak_g3 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20170602"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        // cover vawtrak2 / dga version
        $vaw2dga_0 = "aeiou"
        $vaw2dga_1 = "bcdfghjklmnpqrstvwxyz"
        $vaw2dga_2 = "cdfghlmnrstw"
        $vaw2dga_3 = "index.php"
        
        $vaw2_0 = "aeiou"
        $vaw2_1 = "bcdfghjklmnpqrstvwxyz"
        $vaw2_2 = "@@EMPTY"
        $vaw2_3 = "PID: %u [%0.2u:%0.2u:%0.2u]"
        
        $vaw1_0 = "framework_key%"
        $vaw1_1 = "EQFramework"
        $vaw1_2 = "%s - X32 EQ PID: %u TID: %u"
        $vaw1_3 = "%s - X64 EQ PID: %u TID: %u"
        
    condition:
        all of ($vaw2dga_*) or all of ($vaw2_*) or (3 of ($vaw1_*))
}
