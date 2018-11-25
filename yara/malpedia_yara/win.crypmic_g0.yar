rule win_crypmic_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20170918"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $code_0 = { 8a 56 ?? 46 33 c1 84 d2 75 }
        //$code_1 = { 51 6a 00 6a 00 6a 00 6a 00 ba 76 0a 66 61 }
        $code_2 = { 33 c0 8b cf 66 89 43 02 E8 }
                
        
    condition:
       all of them
}
