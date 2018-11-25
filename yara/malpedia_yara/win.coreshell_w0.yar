rule win_coreshell_w0 {
	meta:
		author = "Florian Roth"
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
		$s0 = "coreshell.dll" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "Core Shell Runtime Service" fullword wide /* PEStudio Blacklist: strings */
	condition:
		all of them
}
