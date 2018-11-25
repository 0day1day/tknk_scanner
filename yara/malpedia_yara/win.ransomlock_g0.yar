rule win_ransomlock_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180102"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $strings_0 = "twexx32.dll" wide
        $strings_1 = "xWindowx" wide
        $cnc_formatstr = "%s?cmd=ul&id=%s" wide
        $useragent = "Mozilla/4.0 (compatible;)" wide

    condition:
       all of them
}
