rule win_krbanker_w0 {
    meta:
        author = "Proofpoint Staff"
        info = "krbanker / blackmoon update"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
            $s1 = "BlackMoon RunTime Error:" nocase wide ascii
            $s2 = "\\system32\\rundll32.exe" wide ascii
            $s3 = "cmd.exe /c ipconfig /flushdns" wide ascii
            $s4 = "\\system32\\drivers\\etc\\hosts.ics" wide ascii

    condition:
            all of them
}
