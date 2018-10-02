rule SAVEfiles_ransom
{
    strings:
        $s1 = "--Admin" wide ascii
        $s2 = "--ForNetRes" wide ascii
        $s3 = "IsAutoStart" wide ascii
        $s4 = "--AutoStart" wide ascii
        $s5 = "--Service" wide ascii
        $s6 = "runas" wide ascii
        $s7 = "IsNotAutoStart" wide ascii
        $s8 = "delself.bat" wide ascii
        $s9 = "goto try" wide ascii
        $s10 = "@echo off" wide ascii
        $s11 = "{\"line1\":\"" wide ascii
        $s12 = "\",\"line2\":\"" wide ascii

    condition:
        all of them
}
