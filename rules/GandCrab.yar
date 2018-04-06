rule GandCrab
{
    strings:
        $string = "GandCrab" wide ascii

    condition:
        $string
}
