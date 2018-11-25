rule win_torrentlocker_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		sample = "unpacked: 8d2e901583b60631dc333d4b396e158b"
        malpedia_version = "20170529"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 

        $dga_alphabet_0 = "eyuioa"
        $dga_alphabet_1 = "qwrtpsdfghjklzxcvbnm"
        
        $command_0 = "_lcfg_set_val_file"
        $command_1 = "_lcfg_get_val_file"
        $command_2 = "rack_lcfg_get_dropper_pe"
        
        $function = { b8 40 00 00 00 68 30 75 00 00 6a 01 (57|56) 50  }
        $winmain_code = { 68 07 7b fb 2a b8 18 00 00 00 }
        
    condition:
        (all of ($dga_alphabet_*)) and 
        ((all of ($command_*)) or $winmain_code or $function)
}
