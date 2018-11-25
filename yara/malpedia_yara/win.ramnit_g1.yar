rule win_ramnit_g1 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180104"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $builderid_0 = "45Bn99gT"
        $builderid_1 = "1E4hNy1O"
        $builderid_2 = "15Bn99gT"
        $useragent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
        $string_antidot = "Antidot is activate"
        $string_mutex = "{%08X-%04X-%04X-%04X-%08X%04X}"
        $string_getexec = "getexec"
        $string_1etexec = "1etexec"

    condition:
       1 of ($builderid_*) and $useragent and 2 of ($string_*)
}
