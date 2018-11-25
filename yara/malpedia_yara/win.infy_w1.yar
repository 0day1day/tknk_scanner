rule win_infy_w1 {
    meta:
        description = "Detects Foudre Backdoor"
        author = "Florian Roth"
        info = "foudre dropper 2"
        reference = "https://goo.gl/Nbqbt6"
        date = "2017-08-01"
        hash1 = "6bc9f6ac2f6688ed63baa29913eaf8c64738cf19933d974d25a0c26b7d01b9ac"
        hash2 = "da228831089c56743d1fbc8ef156c672017cdf46a322d847a270b9907def53a5"
        malpedia_version = "20170803"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "536F594A96C5496CB3949A4DA4775B576E049C57696E646F77735C43757272656E7456657273696F6E5C5C52756E" fullword wide
        $x2 = "2220263024C380B3278695851482EC32" fullword wide

        $s1 = "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\\\Startup\\" fullword wide
        $s2 = "C:\\Documents and Settings\\All Users\\" fullword wide
        $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\\\Shell Folders" fullword wide
        $s4 = "ShellExecuteW" fullword wide
    condition:
        filesize < 100KB and ( 1 of ($x*) or 4 of them ) 
}
