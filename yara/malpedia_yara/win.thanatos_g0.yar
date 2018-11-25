rule win_thanatos_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $string_grab_0 = "----------FIREFOX_FGRAB----------"
        $string_grab_1 = "----------IEXPLORE_FGRAB----------"
        $format_str = "%s\\%s\\%s\\%sent%ssion\\%s"
        $version_str = "Version 0.9.4.2"

    condition:
       all of them
}
