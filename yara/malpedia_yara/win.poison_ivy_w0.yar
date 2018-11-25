rule win_poison_ivy_w0 {
    meta:
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/pivy.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        // presence of pivy in memory
        $a = {00 00 00 00 00 00 00 00 00 00 00 53 74 75 62 50 61 74 68 00} 

    condition: 
        any of them
}
