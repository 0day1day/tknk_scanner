rule win_hikit_w0 {
	meta:
		author = "31ric"
		description = "Backdoor.Hikit is a Trojan horse that opens a back door on the compromised computer."
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/hiddenlynxfiles.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

	strings: 
		$f1 = "w7fw.sys" nocase ascii wide
		$f2 = "w7fw_m.inf" nocase ascii wide
		$f3 = "w7fw.inf" nocase ascii wide
		$f4 = "w7fw.cat" nocase ascii wide
		
	condition:
		1 of them
}
