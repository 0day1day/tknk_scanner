rule win_corebot_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        info = "2017-08+ corebot dropper"
        malpedia_version = "20180125"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $str_0 = "fkit.pdb"
        $bin_0 = { 69 EE 93 01 00 01 0F BE F3 8A 18 40 }

    condition:
       all of them
}
