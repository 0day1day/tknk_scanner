rule win_ccleaner_backdoor_w0 {
    meta:
        author = "Florian Roth"
        reference = "https://goo.gl/puVc9q"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "\\spool\\prtprocs\\w32x86\\localspl.dll" fullword ascii
        $s2 = "\\spool\\prtprocs\\x64\\localspl.dll" fullword ascii
        $s3 = "\\msvcrt.dll" fullword ascii
        $s4 = "\\TSMSISrv.dll" fullword ascii
    condition:
        all of them
}
