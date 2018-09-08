rule AZORult {
    strings:
        $s0 = "PasswordsList.txt"
        $s1 = "Passwords.txt"
        $s2= "ip.txt"
        $s3= "IP.txt"
        $s4 = "System.txt"
        $s5 = "SYSInfo.txt"
        $s6 = "CookieList.txt"
        $constant1 = {85 C0 74 40 85 D2 74 31 53 56 57 89 C6 89 D7 8B 4F FC 57} // Azorult grabs .txt and .dat files from Desktop
        $constant2 = {68 ?? ?? ?? ?? FF 75 FC 68 ?? ?? ?? ?? 8D 45 F8 BA 03 00} // Portion of code from Azorult self-delete function
    condition:
        3 of ($s*) and 1 of ($constant*)
}
