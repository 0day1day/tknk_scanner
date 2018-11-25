rule win_vawtrak_g0 {
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de"
		description = "2015-03-18 Vawtrak"
        malpedia_version = "20170511"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        /* strings related to credential steeling */
        $net_login = "login=%s&pass=%s"
        $net_cookie = "Cookie: disclaimer_accepted=true"
        $net_select_url = "SELECT url FROM moz_places"
        $net_speedy = "network.http.spdy.enabled"

        /* strings related to C&C communication */
        $info_pid = "[%s - X32 EQ PID: %u TID: %u]"
        $info_id = "id=%0.8X%0.8X%0.8X%0.4X%0.4X%0.4X&iv=%0.8X&av=%0.8X&uptime=%u"
        $info_and = "&info=%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.4X%0.2X%0.4X&proxy=%s&name=%ws&domain=%ws"
        $info_agent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"
        $info_botid = "BOT_ID:"
        $info_projectid = "PROJECT_ID:"
        $info_build = "BUILD:"
        $info_updatever = "UPDATE_VER:"

        /* strings of security programs */
        $anti_arcabit = "ArcaBit"
        $anti_solutions = "Online Solutions"
        $anti_anvir = "AnVir Task Manager"
        $anti_alwil = "Alwil Software"
        $anti_zillya = "Zillya Antivirus"
        $anti_sandboxie = "Sandboxie"

        /* other strings */
        $other_vnc1 = "[VNC] Fail create  process: %u"
        $other_vnc2 = "[VNC] Fail inject to process: %u"
        $other_socks1 = "[Socks] Failt connect BC [%s:%u]"
        $other_socks2 = "[Socks] Failt Init BC"
        $other_dl1 = "DL_EXEC LOAD ERROR: %u = %s"
        $other_dl2 = "DL_EXEC Status[Local]: %u = %u"
        $other_proclist = "PROCESS_LIST"
        $other_vidlist = "VIDEO_LIST"
        $other_pony = "[Pony] Fail Get Pass"

    condition:
        (2 of ($net*)) and (4 of ($info*)) and (3 of ($anti*)) and (4 of ($other*))
}
