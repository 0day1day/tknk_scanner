rule win_predator_w0 {
   meta:
        description = "Yara rule for Predator The Thief v2.3.5 & +"
        author = "Fumik0_"
        date = "2018/10/12"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.predator"
        malpedia_version = "20181019"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
   strings:
        $hex1 = { BF 00 00 40 06 } 
        $hex2 = { C6 04 31 6B }
        $hex3 = { C6 04 31 63 }
        $hex4 = { C6 04 31 75 }
        $hex5 = { C6 04 31 66 }

        $s1 = "sqlite_" ascii wide
   condition:
        all of ($hex*) and all of ($s*)
}
