rule GandCrab
{
    strings:
        $s1 = "&version=" wide ascii
        $s2 = "/c timeout -c 5 & del \"%s\" /f /q" wide ascii
        $s3 = "GANDCRAB" wide ascii
        $t1 = "%s\\GDCB-DECRYPT.txt" wide ascii 
        $t2 = "%s\\KRAB-DECRYPT.txt" wide ascii
    condition:
        all of ($s*) and ($t1 or $t2)
}
