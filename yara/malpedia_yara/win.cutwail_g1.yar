rule win_cutwail_g1 {
    meta:
		author="mak"
        info="dropper part"
		module="cutwail"
        malpedia_version = "20170807"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
	strings:
		$smtp="smtp"
		$extract_inner_bins = { 8B 04 95 [4] 89 01 8B 8D 50 FE FF FF 8B 95 54 FE FF FF 89 51 04}
		
	condition:
		all of them
}
