rule win_zezin_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180102"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $pdb_path = "C:\\Users\\vzezj\\Desktop\\bn\\2.0 work\\zezin\\obj\\Release\\ARMsvc.pdb"
        $strings_0 = "Detect detector!" wide
        $strings_1 = "Clear! Start" wide 
        $strings_2 = "zezin" wide
    condition:
       $pdb_path or all of ($strings_*)
}
