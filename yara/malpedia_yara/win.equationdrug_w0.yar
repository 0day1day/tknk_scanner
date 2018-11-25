/* EquationDrug Update 11.03.2015 - http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ */

rule win_equationdrug_w0 {
	meta:
		description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "26e787997a338d8111d96c9a4c103cf8ff0201ce"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/Equation.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
		$s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
		$s3 = "sys\\mstcp32.dbg" fullword ascii
		$s7 = "mstcp32.sys" fullword wide
		$s8 = "p32.sys" fullword ascii
		$s9 = "\\Device\\%ws_%ws" fullword wide
		$s10 = "\\DosDevices\\%ws" fullword wide
		$s11 = "\\Device\\%ws" fullword wide
	condition:
		all of them
}
