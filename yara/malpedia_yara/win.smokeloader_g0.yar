rule win_smokeloader_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		sample = "unpacked: 7bd631b8c5a03eb5676c6dff243d632a"
        malpedia_version = "20170511"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $vm_detection_0 = "qemu"                         // Vm detection by string scanning
        $vm_detection_1 = "virtual"                      // Vm detection by string scanning
        $vm_detection_2 = "vmware"                       // Vm detection by string scanning
        
        $identifier_0 = "s2k13"                          // identifier of smoke loader
        $identifier_1 = "s2k14"                          // identifier of smoke loader
        $identifier_2 = "Smk"
        
        $cnc_cmd_0 = "AAAA"
        $cnc_cmd_1 = "BBBB"
        $cnc_cmd_2 = "CCCC"
        $cnc_cmd_3 = "DDDD" 

        $cncpattern_0 = "cmd=getload&login="             // parameters for C&C traffic
        $cncpattern_1 = "&doubles=1"                     // parameters for C&C traffic
        $cncpattern_2 = "&run=ok"                        // parameters for C&C traffic
        $cncpattern_3 = "Mozilla/4.0"                    // static user agent
        
    condition:
        ((any of ($identifier_*)) or 3 of ($cnc_cmd_*)) and (all of ($vm_detection_*)) and (3 of ($cncpattern_*))
}
