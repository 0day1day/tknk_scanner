rule win_cobra_g0 {
    meta:
	    author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de"
        info = "loader"
        malpedia_version = "20170603"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $str_0 = "srservice" wide
        $str_1 = "ipvpn" wide
        $str_2 = "hkmsvc" wide
        $str_3 = "%c:\\" wide
        $str_4 = "\\inf\\" wide
        

    condition:
        all of them
}
