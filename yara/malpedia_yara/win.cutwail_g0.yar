rule win_cutwail_g0 {
	meta:
		author="mak"
		function="get_config"
        malpedia_version = "20170807"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
	strings:
		$get_strings = { 6B C0 ?? 6a ?? 05 [4] 50 57 E8 [4] C7 46 4A }
		$get_xor  = { 81 39 ?? ?? 00 00 5? BE [4] 72 05 BE }
		$get_version = { 74 07 66 09 ?? [4] 68 [4] 8D [2] C7 05 [4] ?? ?? ?? 00 E8 }
	condition:
		all of them and #get_xor == 1
}

