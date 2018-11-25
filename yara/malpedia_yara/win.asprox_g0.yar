rule win_asprox_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		date = "2014-09-15"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        // contains usable unencrypted strings:
        $cnc_msg = "<knock><id>%s</id><group>%s</group><src>%d</src><transport>%d</transport><time>%d</time><version>%d</version><status>%d</status><debug>%s</debug></knock>"
        $regkey_for_0 = "For base!!!!!"
        $regkey_for_1 = "You fag!!!!!"
        $regkey_for_2 = "For group!!!!!"
        $lure_popup_0 = "Windows cannot open the file."
        $lure_popup_1 = "The Windows might not support the file type or might not support the codec that was used to compress the file."
        $user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0"        
        
    condition:
       $cnc_msg or ((all of ($regkey_for_*)) and (all of ($lure_popup_*)) and $user_agent)
}
