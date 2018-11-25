import "pe"

rule win_syscon_w0 {
    meta:
        author = "Florian Roth"
        reference = "https://goo.gl/JAHZVL"
        date = "2018-03-03"
        hash1 = "d31fe5cfa884e04ee26f323b8d104dcaa91146f5c7c216212fd3053afaade80f"
        hash2 = "fc2bcd38659ae83fd25b4f7091412ae9ba011612fa4dcc3ef665b2cae2a1d74f"
        hash3 = "2c5e5c86ca4fa172341c6bcbaa50984fb168d650ae9a33f2c6e6dccc1d57b369"
        hash4 = "439c305cd408dbb508e153caab29d17021a7430f1dbaec0c90ac750ba2136f5f"
        malpedia_version = "20170809"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "cmd /c taskkill /im cliconfg.exe /f /t && del /f /q" fullword ascii
        $x2 = "\\FTPCom_vs10\\Release\\Engine.pdb" ascii
        $x3 = "KXU/yP=B29tLzidqNRuf-SbVInw0oCrmWZk6OpFc7A5GTD1QxaJ3H8h4jMeEsYglv" fullword ascii
        $x4 = "D:\\Task\\MiMul\\" ascii

        $s1 = "[DLL_PROCESS_ATTACH]" fullword ascii
        $s2 = "cmd /c systeminfo >%s" fullword ascii
        $s3 = "post.txt" fullword ascii
        $s4 = "\\temp.ini" fullword ascii
        $s5 = "[GetFTPAccountInfo_10001712]" fullword ascii
        $s6 = "ComSysAppMutex" fullword ascii
        $s7 = "From %s (%02d-%02d %02d-%02d-%02d).txt" fullword ascii
        $s8 = "%s %s %c%s%c" fullword ascii
        $s9 = "TO EVERYONE" fullword ascii
    condition:
        pe.imphash() == "e14b59a79999cc0bc589a4cb5994692a" or pe.imphash() == "64400f452e2f60305c341e08f217b02c" or 1 of ($x*) or 3 of them
}
