rule win_locky_a0 {

    meta: 
        author = "pnx"
        info = "created with malpedia YARA rule editor"
        malpedia_version = "20171001"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        // Locky uses a custom and very customizable jump-based obfuscation since versions first showing in August 2017
        $jmp_obf_1 = { cc cc cc cc 55 90 }
        $jmp_obf_2 = { cc cc cc cc 8b 01 90 }

    condition:
        #jmp_obf_1 > 10 and #jmp_obf_2 > 10
}
