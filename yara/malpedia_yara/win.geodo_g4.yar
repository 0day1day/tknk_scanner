rule win_geodo_g4 {
	meta:
		author="mak"
		module="emotet"
		function="emotet4_spam"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	strings:
		$login="LOGIN" fullword
		$startls="STARTTLS" fullword
		$mailfrom="MAIL FROM:"

        $emotet4_rsa_public = { 8d ?? ?? 5? 8d ?? ?? 5? 6a 00 68 00 80 00 00 ff 35 [4] ff 35 [4] 6a 13 68 01 00 01 00 ff 15 [4] 85 }
		$emotet4_cnc_list   = {  39 ?? ?5 [4] 0f 44 ?? (FF | A3)}

	condition:
		all of them
}
