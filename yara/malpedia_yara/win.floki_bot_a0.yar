rule win_floki_bot_a0 {
    meta:
        author = "Vitali Kremez, Flashpoint"
        version = "20161106"
        malpedia_version = "20180122"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $s0 = "%s\\SysWOW64\\explorer.exe" fullword wide
        $s1 = "%s\\SysWOW64\\svchost.exe" fullword wide
        $s2 = "%s\\svchost.exe" fullword wide
        $s3 = "Hash: 0x%x not loaded." fullword ascii

        $op0 = { 7f 11 e8 a0 f3 ff ff 83 7d 16 07 7e 27 e8 53 f6 }
        $op1 = { c3 ff 45 23 fe 45 22 80 7d 22 0f 75 06 e8 35 fa }
        $op2 = { e8 82 fe ff ff c3 83 7d 16 02 75 10 83 7d 0a 03 }
            
    condition:
        all of ($s*) and 1 of ($op*)
}

