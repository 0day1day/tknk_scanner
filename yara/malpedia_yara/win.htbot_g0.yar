rule win_htbot_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		description = "Unpacked binary in memory"
		sample = "a530aa5c6d8ff62743d719e71762f35d98dca90bfd025cfaca26bc961b94b155"
        malpedia_version = "20170529"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $cnc_1 = "?command=getid" wide
        $cnc_2 = "?command=getip" wide
        $cnc_3 = "?command=getbackconnect" wide
        $cnc_4 = "?command=version&id=%s" wide
        $cnc_5 = "%s?command=update&id=%s&ip=%s&port=%d" wide
        $cnc_6 = "%s?command=update2&id=%s&ip=%s&port=%d" wide
        $cnc_7 = "%s?command=ghl&id=%s" wide
        $cnc_8 = "%s?command=dl&id=%s" wide
        
        $mutex = "PB_MAIN_MUTEX" wide

    condition:
        (5 of ($cnc_*)) and $mutex
}
