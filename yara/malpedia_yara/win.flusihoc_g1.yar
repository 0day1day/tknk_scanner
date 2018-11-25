rule win_flusihoc_g1 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180104"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $pdb = "C:\\Users\\chengzhen\\Desktop\\"
        $format_svc = "%ssvchost.exe"
        $regkey = "mainspoolsv"

    condition:
       all of them
}
