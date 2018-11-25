rule win_necurs_g1 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        info = "targets the Necurs spam module"
        malpedia_version = "20180103"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $spam_template_0 = "rndhex"
        $spam_template_1 = "rndnum"
        $spam_template_2 = "rndnum"
        $spam_template_3 = "strip_tags"
        $format_str = "%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X@%s"

    condition:
       2 of ($spam_template_*) and $format_str
}
