rule win_csext_w0 {
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
		$s1 = "COM+ System Extentions"
		$s2 = "csext.exe"
		$s3 = "COM_Extentions_bin"
	condition:
		all of them
}
