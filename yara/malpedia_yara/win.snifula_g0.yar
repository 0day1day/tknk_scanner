rule win_snifula_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		description = "Unpacked binary in memory"
		sample = "104428ccf005b36edfb62d110203a43bdbb417052b31eb4646395309645c9944"
        malpedia_version = "20170529"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $cnc_1 = "user_id=%.4u&version_id=%lu&socks=%lu&build=%lu&crc=%.8x"
        $cnc_2 = "NEWGRAB" 
        $cnc_3 = "user=%s&pass=%s" 
        $cnc_4 = "Content-Disposition: form-data; name=\"upload_file\"; filename=\"%.4u.%lu\"" 
        $cnc_5 = "CLEAR_COOK" 
        $cnc_6 = "GET_CERTS" 

    condition:
        all of ($cnc_*)
}
