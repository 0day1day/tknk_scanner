rule Zeus_Variant
{
    strings:
        $s0 = "%BOTID%"
        $s1 = "%BOTNET%"
        $s2 = "%BC-*-*-*-*%"
        $s3 = "%VIDEO%"
        $s4 = "Psystem"
        $s5 = "registry"
        $s6 = "setvalue"
        $s7 = "getvalue"
        $s8 = "hvnc_stop"
        $s9 = "hvnc_start"
        $s10 = "video_start"
        $s11 = "bc_remove"
        $s12 = "bc_add"
    condition:
        all of them
}

 	














