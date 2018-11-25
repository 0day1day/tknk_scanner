rule win_citadel_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de"
		description = "2013-06-23 Citadel (1.3.0.0 - 3.1.0.0)"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $a = "Coded by BRIAN KREBS for personal use only. I love my job & wife."
        $b = "http://%02x%02x%02x%02x%02x%02x%02x%02x.com/%02x%02x%02x%02x/%02x%02x%02x%02x%02x.php"
        $c = "%BOTID%"
        $d = "%BOTNET%"
        $e = "cit_video.module"
        $f = "bc_remove"
        $g = "bc_add"
        $h = "http://www.google.com/webhp"

    condition:
        ($a) or ($b) or (5 of ($c,$d,$e,$f,$g,$h))
}
