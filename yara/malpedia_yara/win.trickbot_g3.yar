rule win_trickbot_g3 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        info = "more relaxed rule, primarily targeting modules"
        malpedia_version = "20180125"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        // <moduleconfig>...<autostart>
        $bin_moduleconfig_0 = { 3C 6D 6F 64 75 6C 65 63 6F 6E 66 69 67 3E [0-10] 3C 61 75 74 6F 73 74 61 72 74 3E }
        // <moduleconfig>...</moduleconfig>
        $bin_moduleconfig_1 = { 3C 6D 6F 64 75 6C 65 63 6F 6E 66 69 67 3E [0-10] 3C 2F 6D 6F 64 75 6C 65 63 6F 6E 66 69 67 3E }
        // \\.\pipe\pidplacesomepipe
        $bin_banker = { 5C 5C 2E 5C 70 69 70 65 5C 70 69 64 70 6C 61 63 65 73 6F 6D 65 70 69 70 65 }
        $str_outlook = "OutlookX32.dll"

    condition:
       any of them
}
