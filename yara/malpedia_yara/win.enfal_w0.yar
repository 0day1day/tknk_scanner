rule win_enfal_w0 {
    meta:
        author = "Florian Roth"
        description = "Generic Rule to detect the Enfal Malware"
        date = "2015/02/10"
        hash0 = "6d484daba3927fc0744b1bbd7981a56ebef95790"
        hash1 = "d4071272cc1bf944e3867db299b3f5dce126f82b"
        hash2 = "6c7c8b804cc76e2c208c6e3b6453cb134d01fa41"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:

        $s1 = "Micorsoft Corportation" fullword wide
        $s2 = "IM Monnitor Service" fullword wide

        $x1 = "imemonsvc.dll" fullword wide
        $x2 = "iphlpsvc.tmp" fullword
        $x3 = "{53A4988C-F91F-4054-9076-220AC5EC03F3}" fullword

        $z1 = "urlmon" fullword
        $z2 = "Registered trademarks and service marks are the property of their" wide
        $z3 = "XpsUnregisterServer" fullword
        $z4 = "XpsRegisterServer" fullword
    condition:
        (( 1 of ($s*)) or ( 2 of ($x*) and all of ($z*) ))
}
