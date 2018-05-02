rule GandCrab
{
    strings:
        $string = ".CRAB" wide ascii
        $b1 = {C7 44 24 40 26 00 76 00 C7 44 24 44 65 00 72 00  C7 44 24 48 73 00 69 00 C7 44 24 4C 6F 00 6E 00}

    condition:
        $string and $b1
}
