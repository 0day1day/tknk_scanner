rule win_jripbot_w0 {
	meta:
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
		$s0 = "LiveUpdater.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '25.00' */
		$s1 = "id-at-postalAddress" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00' */
		$s2 = "%d -> %d (default)" fullword wide /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide /* score: '15.00' */
		$s8 = "id-ce-keyUsage" fullword ascii /* score: '12.00' */
		$s9 = "Key Usage" fullword ascii /* score: '12.00' */
		$s32 = "UPDATE_ID" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00' */
		$s37 = "id-at-commonName" fullword ascii /* score: '8.00' */
		$s38 = "2008R2" fullword wide /* PEStudio Blacklist: os */ /* score: '8.00' */
		$s39 = "RSA-alt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.00' */
		$s40 = "%02d.%04d.%s" fullword wide /* score: '7.02' */
	condition:
		all of them
}
