rule win_xxmm_w0 {
    meta:
        author = "Florian Roth"
        description = "Detects malware / hacktool sample from Bronze Butler incident"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "\\Release\\ReflectivLoader.pdb" ascii
        $x3 = "\\Projects\\xxmm2\\Release\\" ascii
        $x5 = "http://127.0.0.1/phptunnel.php" fullword ascii

        $s1 = "xxmm2.exe" fullword ascii
        $s2 = "\\AvUpdate.exe" fullword wide
        $s3 = "stdapi_fs_file_download" fullword ascii
        $s4 = "stdapi_syncshell_open" fullword ascii
        $s5 = "stdapi_execute_sleep" fullword ascii
        $s6 = "stdapi_syncshell_kill" fullword ascii
    condition:
        1 of ($x*) or
        4 of them
}
