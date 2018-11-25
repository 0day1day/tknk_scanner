rule win_extreme_rat_w1 {
    meta:
        description = "XtremeRAT"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-09"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/xTremRat.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    
    strings:
        // call; fstp st
        $code1 = { E8 ?? ?? ?? ?? DD D8 }
        // hiding string
        $code2 = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }
        $str1 = "dqsaazere"
        $str2 = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"
        
    condition:
       all of ($code*) or any of ($str*)
}

