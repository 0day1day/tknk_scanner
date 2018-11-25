rule zloader_g0 {
	meta:
		author = "mak"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
	strings:
		$get_cfg0 = { BE ?? ?? 00 00 56 68 [4]  57 E8 [4] 68 [4] 56 57 }
		$get_cfg1 = { C7 44 24 08 ?? ?? 00 00 C7 44 24 04 [4] E8 [4] 89 34 ?? C7 44 24 [5] C7 44 }

		$str1 = "_Start@4" fullword
		$str2 = "payload.dll" fullword
		$str3 = "VM is not supported." fullword
		$str4 = ".bit" fullword
		$str5 = ".dll" fullword
		
		$fmt0 = "%x%x%x%x%x%x%x" fullword 
		$fmt1=  "%x%x%x%x%x%x" fullword
		
		$prolog  = { 55 8B EC 81 EC [4] FF 4D 0C 0F [2] 00 00 00 E8 [4] E8 [4] E8 [4] E8 [4] (E8 | 8D)}

	condition:
		(2 of ($str*) and 1 of ($fmt*) and 1 of ($get_cfg*)) and $prolog
}
