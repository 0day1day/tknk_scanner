rule win_badflick_w0 {
    meta:
		description = "Detects BADFLICK backdoor"
		author = "@VK_Intel"
		reference = "BADFLICK backdoor"
		date = "2018-03-26"
		hash = "7ba05abdf8f0323aa30c3d52e22df951eb5b67a2620014336eab7907b0a5cedf"
		reference = "https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badflick"
		malpedia_version = "20180407"
		malpedia_license = "CC BY-NC-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
    strings:
		$s0 = "%s\\en-US\\cmd.exe.mui" fullword wide
		$s1 = "[Green] pid=%d tid=%d modulePath=%s|" fullword wide
		$s2 = "1|103.243.175.181|80|5|xxxxxxxxxxxxxxxxxxxxxxx" wide ascii
		$s3 = "modulePath=%[^|]" fullword wide
		$s4 = "%s:%d:%s:%d:%d" fullword ascii
		$s5 = "regsvr32 %s %s %s go \"%s\"" fullword wide
		$s6 = "modulePath=" fullword wide
		$s7 = "%d %d.%d.%d %s" fullword wide
		$s8 = "winMain static green" fullword wide
		$s9 = "o%d Core %.2f GHz" fullword wide
		$s10 = "6&62676=6B6G6N6c6s6" fullword ascii

		$op0 = { 8b 54 24 54 8b cf 2b cb 8d 04 0a 3b c7 76 02 8b } 
		$op1 = { a1 08 77 40 00 89 45 94 8d 45 94 50 ff 35 04 77 } 
		$op2 = { 8b 7c 24 14 8b f7 2b f5 8d 64 24 00 8a 1f 84 db }
	condition:
		uint16(0) == 0x5a4d and filesize < 108KB and 8 of ($s*) and 1 of ($op*)
}
