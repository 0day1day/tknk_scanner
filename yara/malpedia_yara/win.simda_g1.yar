rule win_simda__g1 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		description = "Alternative rule, targeting the DGA"
		sample = "49be9fae1ff526212cd59b43b910502bf5f9342a8e7ce93d8ba7dffc4134d154"
        malpedia_version = "20170529"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings: 
        $dga_alphabet_0 = "eyuioa"
        $dga_alphabet_1 = "qwrtpsdfghjklzxcvbnm"
        $dga_add_config = { 0f be c0 41 03 d0 8a 01 84 c0 75 f4 }
        $dga_choose_alpha = { 33 d2 f7 f1 33 d2 bb (14|06) 00 00 00 f7 f3 8a 54 }
    condition:
        all of ($dga_alphabet_*) and $dga_add_config and #dga_choose_alpha > 1
}
