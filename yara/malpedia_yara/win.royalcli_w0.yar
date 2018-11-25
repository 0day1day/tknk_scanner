import "pe"

rule win_royalcli_w0 {
    meta:
        description = "Detects malware from APT 15 report by NCC Group"
        author = "Florian Roth"
        reference = "https://goo.gl/HZ5XMN"
        date = "2018-03-10"
        hash1 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"
        malpedia_version = "20180312"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "\\Release\\RoyalCli.pdb" ascii
        $s2 = "%snewcmd.exe" fullword ascii
        $s3 = "Run cmd error %d" fullword ascii
        $s4 = "%s~clitemp%08x.ini" fullword ascii
        $s5 = "run file failed" fullword ascii
        $s6 = "Cmd timeout %d" fullword ascii
        $s7 = "2 %s  %d 0 %d" fullword ascii
    condition:
        2 of them
}
