rule win_rombertik_w4 {
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder Server - file Server.exe"
		author = "Florian Roth"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "895fab8d55882eac51d4b27a188aa67205ff0ae5"
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        
	strings:
		$s0 = "C:\\WINDOWS\\system32\\svchost.exe" fullword ascii
		$s3 = "Software\\Microsoft\\Windows\\Currentversion\\RunOnce" fullword ascii
		$s4 = "chrome.exe" fullword ascii
		$s5 = "firefox.exe" fullword ascii
		$s6 = "chrome.dll" fullword ascii
		$s7 = "@KERNEL32.DLL" fullword wide
		$s8 = "Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome" ascii
		$s10 = "&post=" fullword ascii
		$s11 = "&host=" fullword ascii
		$s12 = "Ws2_32.dll" fullword ascii
		$s16 = "&browser=" fullword ascii
		
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and 8 of them
}
