rule win_powerpool_g1 {
    meta:
        description = "Identify potential PowerPool malware stage 2"
        author = "blevene @upperCase, Chronicle Security"
        version = "1.0"
        date = "09-06-2018"
        TLP = "GREEN"
        reference = "https://www.welivesecurity.com/2018/09/05/powerpool-malware-exploits-zero-day-vulnerability/"
        hash = "58a50840c04cd15f439f1cc1b684e9f9fa22c0d64f44a391d9e2b1222e5cd6bd"
        malpedia_version = "20180907"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        //Error Strings
        $s1 = "no use" ascii
        $s2 = "bad cast" ascii
        $s3 = "GetLastError-->%u" ascii
        $s4 = "open internet failed..." ascii
        $s5 = "connect failed..." ascii
        $s6 = "handle not opened..." ascii
        $s7 = "add cookie failed..." ascii

        //differentiate from Jaku using weird strings
        //anchor string
        $a1 = "may i print it" ascii
        $a2 = "corrupted regex pattern" ascii
 
    condition:
        4 of ($s*) and 1 of ($a*)
}
