rule win_synflooder_w0 {
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
		$s1 = "Unable to resolve [ %s ]. ErrorCode %d"
		$s2 = "your target’s IP is : %s"
		$s3 = "Raw TCP Socket Created successfully."
	condition:
		all of them
}
