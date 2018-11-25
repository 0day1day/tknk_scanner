rule win_hawkeye_keylogger_w0 {
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2015/06"
		ref = "http://malwareconfig.com/stats/HawkEye"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/HawkEye.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

	strings:
		$key = "HawkEyeKeylogger" wide
		$salt = "099u787978786" wide
		$string1 = "HawkEye_Keylogger" wide
		$string2 = "holdermail.txt" wide
		$string3 = "wallet.dat" wide
		$string4 = "Keylog Records" wide
    $string5 = "<!-- do not script -->" wide
    $string6 = "\\pidloc.txt" wide
    $string7 = "BSPLIT" wide

	condition:
		$key and $salt and all of ($string*)
}
