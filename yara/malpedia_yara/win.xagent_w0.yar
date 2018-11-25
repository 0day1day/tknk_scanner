rule win_xagent_w0 {
    meta:
        description = "Sofacy Group Malware Sample 3"
        author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "5f6b2a0d1d966fc4f1ed292b46240767f4acb06c13512b0061b434ae2a692fa1"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/sofacy_xtunnel_bundestag.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" fullword ascii 
        $s2 = ".?AVAgentModuleRemoteKeyLogger@@" fullword ascii 
        $s3 = "<font size=4 color=red>process isn't exist</font>" fullword ascii 
        $s4 = "<font size=4 color=red>process is exist</font>" fullword ascii 
        $s5 = ".winnt.check-fix.com" fullword ascii 
        $s6 = ".update.adobeincorp.com" fullword ascii 
        $s7 = ".microsoft.checkwinframe.com" fullword ascii
        $s8 = "adobeincorp.com" fullword wide 
        $s9 = "# EXC: HttpSender - Cannot create Get Channel!" fullword ascii 

        $x1 = "User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/" wide 
        $x2 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/2" wide 
        $x3 = "C:\\Windows\\System32\\cmd.exe" fullword wide 
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and (
            2 of ($s*) or 
            ( 1 of ($s*) and all of ($x*) )
        ) 
}
