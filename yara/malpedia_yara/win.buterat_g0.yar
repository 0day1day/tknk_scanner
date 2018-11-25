rule win_buterat_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180102"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $cnc_commands_0 = "ZORKASITE" wide
        $cnc_commands_1 = "BEGUNFEED" wide
        $cnc_commands_2 = "REKLOSOFT" wide
        $cnc_commands_3 = "LIVINETCH" wide
        $cnc_commands_4 = "COOKREJCT" wide
        $cnc_commands_5 = "SUPERPOISK" wide

    condition:
       all of them
}
