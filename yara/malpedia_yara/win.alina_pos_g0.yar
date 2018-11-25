rule win_alina_pos_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180114"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $string_alina = "Alina v"
        $grab_str_0 = "([0-9]{13,19}=(1[2-9])(0[1-9]|1[0-2])[0-9]{3,50}\\?)"
        $grab_str_1 = "{[!22!]}{[!5!]}%s -> %s [%d]{[!35!]}= 0x%x (== 0x%x)"

    condition:
       $string_alina and 1 of ($grab_str_*)
}
