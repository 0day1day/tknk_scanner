rule win_troldesh_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        date = "2017-09-06"
        description = "Unpacked Shade binary, non-statically-linked part and specific strings (vs. CMSBrute)"
        malpedia_version = "20170907"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $common_code_0 = { 25 ff ff ff bf 8b c8 8b d? 8b c6 f0 0f b1 0a 3b c6 74 }
        $common_code_1 = { 6a 00 81 c3 00 80 c1 2a 68 80 96 98 00 }
        $ini_files = "desktop.ini|boot.ini"

    condition:
       all of them
}
