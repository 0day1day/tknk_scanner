rule win_jaff_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20170605"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $single_byte_lcg = { 69 c9 fd 43 03 00 
                             81 c1 c3 9e 26 00
                             8b c1
                             c1 e8 10 
                             25 ff 7f 00 00 
                             99
                             bb fe 00 00 00
                             f7 fb
                           }
        
    condition:
        all of them
}
