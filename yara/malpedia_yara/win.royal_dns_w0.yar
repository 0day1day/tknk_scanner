import "pe"

rule win_royal_dns_w0 {
    meta:
        description = "Detects malware from APT 15 report by NCC Group"
        author = "Florian Roth"
        reference = "https://goo.gl/HZ5XMN"
        date = "2018-03-10"
        hash1 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
        malpedia_version = "20180312"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "del c:\\windows\\temp\\r.exe /f /q" fullword ascii
        $x2 = "%s\\r.exe" fullword ascii

        $s1 = "rights.dll" fullword ascii
        $s2 = "\"%s\">>\"%s\"\\s.txt" fullword ascii
        $s3 = "Nwsapagent" fullword ascii
        $s4 = "%s\\r.bat" fullword ascii
        $s5 = "%s\\s.txt" fullword ascii
        $s6 = "runexe" fullword ascii
    condition:
        1 of ($x*) or 2 of them
}
