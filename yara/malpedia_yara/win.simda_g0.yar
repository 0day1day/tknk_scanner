rule win_simda_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		description = "Some DGA-based family, active since (?) 2013. MS calls it Simda. Detects versions 4.4.x, 4.5.x, 4.8.x, 4.14.x (and likely more of 4.x)"
		sample = "5c1aee515bce62c0e3c99710cc1cce18"
        malpedia_version = "20170511"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings: 
        $VNC_init = "RFB 003.006"
        $CNC_checkin_v4_8_0 = "hid=%s"
        $CNC_checkin_v4_8_1 = "&username="
        $CNC_checkin_v4_8_2 = "&compname=%s"
        $CNC_checkin_v4_8_3 = "&bot_version="
        $CNC_checkin_v4_8_4 = "&uptime=%u"
        $CNC_checkin_v4_8_5 = "&os=%04u"
        $CNC_checkin_v4_8_6 = "&local_time=%s%d"
        $CNC_checkin_v4_8_7 = "&token=%d"
        $CNC_checkin_v4_8_8 = "&socks_port=%u"
        $CNC_checkin_v4_8_9 = "&hardware[display]=%s"
        $CNC_checkin_v4_8_10 = "&hardware[driver_av]=%s"

        $CNC_checkin_v4_14_0 = "{BotVer: "
        $CNC_checkin_v4_14_1 = "{Process: "
        $CNC_checkin_v4_14_2 = "{Username: "
        $CNC_checkin_v4_14_3 = "{Processor: "
        $CNC_checkin_v4_14_4 = "{Language: "
        $CNC_checkin_v4_14_5 = "{Screen: "
        $CNC_checkin_v4_14_6 = "{Date: "
        $CNC_checkin_v4_14_7 = "{Uptime: "
        
        $CNC_checkin_v4_14_8 = "&botid=%s"
        $CNC_checkin_v4_14_9 = "&up=%u"
        $CNC_checkin_v4_14_10 = "&rights=%s"
        $CNC_checkin_v4_14_11 = "&ltime=%s%d"
        
        $mutex = "internal_wutex_0x"
        $inject_delimiter_0 = "data_before"
        $inject_delimiter_1 = "data_end"
        $inject_delimiter_2 = "data_inject"
        $inject_delimiter_3 = "data_after"
        $dga_alphabet_0 = "eyuioa"
        $dga_alphabet_1 = "qwrtpsdfghjklzxcvbnm"
    condition:
        $mutex and ((8 of ($CNC_checkin_*))) or ($VNC_init and (all of ($dga_alphabet_*)) and (all of ($inject_delimiter_*)))
}
