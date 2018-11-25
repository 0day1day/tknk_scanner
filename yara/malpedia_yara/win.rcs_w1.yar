rule win_rcs_w1 {
	meta:
		description = "Hacking Team Disclosure Sample - file ndisk.sys"
		author = "Florian Roth"
		reference = "https://www.virustotal.com/en/file/a03a6ed90b89945a992a8c69f716ec3c743fa1d958426f4c50378cca5bef0a01/analysis/1436184181/"
		date = "2015-07-07"
		hash = "cf5089752ba51ae827971272a5b761a4ab0acd84"
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
		$s1 = "\\Registry\\Machine\\System\\ControlSet00%d\\services\\ndisk.sys" fullword wide 
		$s2 = "\\Registry\\Machine\\System\\ControlSet00%d\\Enum\\Root\\LEGACY_NDISK.SYS" fullword wide 
		$s3 = "\\Driver\\DeepFrz" fullword wide
		$s4 = "Microsoft Kernel Disk Manager" fullword wide 
		$s5 = "ndisk.sys" fullword wide
		$s6 = "\\Device\\MSH4DEV1" fullword wide
		$s7 = "\\DosDevices\\MSH4DEV1" fullword wide
		$s8 = "built by: WinDDK" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 6 of them
}
