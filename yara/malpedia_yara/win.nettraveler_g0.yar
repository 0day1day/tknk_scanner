rule win_nettraveler_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        date = "2017-08-04"
        malpedia_version = "20170804"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $s0 = "Microsoft_WinInet_"
        $s1 = "SD_2013 Is Running!"
        $s2 = "Decrypt url error!"
        $s3 = "%s?aaaa="
        $s4 = "LeftSpace%lldGB"
        $s5 = "TotalSpace%lldGB"
        $s6 = "Memory: Total:%dMB,Left:%dMB (for %.2f%s)"

    condition:
        4 of them
}
