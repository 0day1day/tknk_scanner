rule win_cadelspy_w2 {
    meta:
        source = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1  = "SOFTWARE\\ntsvc32\\HDD" wide ascii
        $s2  = "SOFTWARE\\ntsvc32\\ROU" wide ascii
        $s3  = "SOFTWARE\\ntsvc32\\HST" wide ascii
        $s4  = "SOFTWARE\\ntsvc32\\FLS" wide ascii
        $s5  = "ntsvc32" wide ascii
        $s6  = ".Win$py." wide ascii
        $s7  = "C:\\users\\" wide ascii
        $s8  = "%system32%" wide ascii
        $s9  = "\\Local Settings\\Temp" wide ascii
        $s10 = "SVWATAUAVAW" wide ascii
        $s11 = "\\AppData\\Local" wide ascii
        $s12 = "\\AppData" wide ascii
    condition:
        6 of them
}
