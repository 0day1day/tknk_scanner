rule win_golroted_w0 {
    meta:
        description = "Golroted Trojan rule - file golroted.exe"
        author = "@VK_Intel"
        reference = "Detects Golroted Trojan"
        date = "2017-11-11"
        hash = "e73b20f639cd9ecc4c8196e885de57043a4baddb70bb4b66e1df13abc7da487e"
        malpedia_version = "20171214"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $s0 = "C:\\Windows\\System32\\Mycomput.dll" fullword ascii
        $s1 = ".lnk\" \"C:\\Users\\" fullword ascii
        $s2 = "vbc.exe" fullword ascii 
        $s3 = "System32\\WerFault.exe" fullword ascii
        $s4 = "system32\\notepad.exe" fullword ascii
        $s5 = "Mozilla Firefox\\firefox.exe" fullword ascii
        $s6 = "FC:\\Windows\\System32\\" fullword ascii
        $s7 = "C:\\Windows\\SysWOW64\\ntdll.dll" fullword ascii
        $s9 = "Microsoft.NET\\Framework\\v2.0.50727\\regasm.exe" fullword ascii
        $s10 = "Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe" fullword ascii
        $s11 = "/c reg add hkcu\\Environment /v windir /d \"cmd /c start " fullword ascii
        $s12 = "bindedfiledropandexecute" fullword ascii
        $s13 = "/c schtasks /Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I && exit" fullword ascii
        $s14 = "Microsoft.NET\\Framework\\v2.0.50727\\vbc.exe" fullword ascii
        $s15 = "Microsoft.NET\\Framework\\v4.0.30319\\vbc.exe" fullword ascii
        $s16 = "C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Internet Security " fullword ascii
        $s17 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" fullword ascii
    condition:
        all of them
}

