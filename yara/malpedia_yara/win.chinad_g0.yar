rule win_chinad_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		date = "2016-11-03"
		description = "Chinad as referenced by 360netlab: https://github.com/360netlab/DGA/issues/1"
		sample = "unpacked:cfb94506f4816034410ecd86a378b9f29b912ecb68c88c8ae0bcad748968cb6c"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings: 
        $dga_alphabet = "abcdefghijklmnopqrstuvwxyz0123456789" ascii
        $cnc_0 = "cnc_reset"
        $cnc_1 = "report"
        $cnc_2 = "report_reset"
        $cnc_3 = "url_exec"
        $cnc_4 = "shellcode_exec"
        $cnc_5 = "attack_reset"
    condition:
        all of them
}
