rule win_chthonic_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		date = "2017-05-15"
		sample = "5124f1b8847074cf927f1fe6dec6657a3a50c32e924f7ff915c926604c207b25"
        malpedia_version = "20170515"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $chthonic_push_bot_version = { 68 13 27 00 00 }
        $chthonic_push_specific_field_1 = { 68 38 27 00 00 }
        $chthonic_push_specific_field_2 = { 68 39 27 00 00 }
        $get_relative_addr = { 55 8B EC E8 00 00 00 00 58 2D ?? ?? ?? ?? 5D C3 } 

    condition:
        (all of ($chthonic_push_*)) and $get_relative_addr
}
