rule win_wonknu_a0 {
    meta:
        id = 137
        revision = 1
        date = "Dec 2 2015"
        description = "Yara rule for Wonknu"
        reference = "https://labsblog.f-secure.com/2015/11/24/wonknu-a-spy-for-the-3rd-asean-us-summit/"
        md5hashes = "564397dcab81a69e50ad8d3d271afedf"
        malpedia_version = "20180912"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"
    strings:
        $opcode1 = { 89 45 FC 8B 45 08 53 48 56 57 8B D9 83 F8 0C }  // 004029EA - opcodes before 13 switch cases
        $rat_string1 = "CmeShell"
        $rat_string2 = "DelFile"
        $rat_string3 = "RunExeFile"
        $rat_string4 = "GetFilelist"
        $rat_string5 = "GetDiskinfo"

    condition:
        $opcode1 or (all of ($rat_string*))
}
