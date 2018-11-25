rule win_9002_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180125"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $str_xlbug_0 = "XLBugHandler"
        $str_xlbug_1 = "xlbug.dat"

    condition:
       any of them
}
