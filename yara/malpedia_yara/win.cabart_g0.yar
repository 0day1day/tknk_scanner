rule win_cabart_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		date = "2014-09-26"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $timestamp = "\x00\x00\x00\x00DATA" ascii
        $nesting = "%stemp_cab_%d.cab" wide ascii
        $ua_0 = "Opera/9.25 (Windows NT 6.0; U; cn)" wide ascii  // static user agent (crypted URLs)
        $ua_1 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)" wide ascii  // static user agent (plain URLs)
        $connection_test = "windowsupdate.microsoft.com" wide ascii         // online check
        
        
    condition:
        $timestamp and $nesting and (any of ($ua_*)) and $connection_test
}
