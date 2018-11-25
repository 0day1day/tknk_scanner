rule win_molerat_loader_g0 {
    meta:
        description = "Detects Downloader"
        author = "Florian Roth"
        reference = "http://www.clearskysec.com/iec/"
        date = "2017-03-13"
        hash1 = "15b5fb226689fdddc04c3e6ddeb84e3aae4ce009cc4c95f6fa68045033ca905f"
        hash2 = "1b7ab355fe28efc14c6a5a7a0f663507a6cdc921ecbadf228005d9f635852463"
        hash3 = "143313a610b77d03202a23bc08f0721de693782d07d27e0dac89004cc1cf9ea3"
        hash4 = "a6a71a00b1f1e2b37332b461611615f98f3aefc57c0274cf1ab217b66149912a"
        hash5 = "f434ec69bf2f6310a8fa5e2dccb3b05e94584a4ab03898da101eaed703737d20"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $x1 = "\\Downloader\\Release\\Downloader.pdb" ascii
        $x2 = "\\tsDownloader\\Release\\tsDownloader.pdb" ascii

        $x3 = " /c wmic /Node:localhost /Namespace:\\\\root\\SecurityCenter Path AntiVirusProduct Get displayName /Format:List > " fullword wide
        $x4 = "\\temp1.txt && wmic path win32_physicalmedia get SerialNumber > " fullword ascii
        $x5 = "\\ProgramData\\system.dll" fullword ascii
        $x6 = " /c wmic NICCONFIG WHERE IPEnabled=true GET IPAddress /format:csv > " fullword wide
        $x7 = "/ProgramData/system.dll" fullword ascii
        $x8 = "\\ProgramData\\dll.dll" fullword wide

        $s1 = "$ie = new-object -comobject InternetExplorer.Application; $ie.Visible = $false; $ie.Silent = $true; $ie.navigate('http://" fullword wide
        $s2 = "dasHost.exe" fullword ascii
        $s3 = "/ProgramData/System Update/check.txt" fullword wide
        $s4 = "Explorer.Exe" fullword wide
        $s5 = "svchosts.Exe" fullword wide
        $s6 = "C:/ProgramData/window/" fullword wide

        $op1 = { 68 72 8d 42 00 8d 4c 24 08 c7 44 24 08 } /* Opcode */
    condition:
        ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) or 2 of ($s*) ) ) or ( 4 of them )
}
