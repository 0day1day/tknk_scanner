rule win_medusa_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        kudos = "TJ Nelson, Arbor"
        malpedia_version = "20171219"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_c1    = "\x00stop-all"
        $str_c2    = "\x00smartflood"
        $str_c3    = "\x00httpstrong:"
        $str_c4    = "\x00httppost:"
        $str_c5    = "\x00httpssl"
        $str_d1    = "xyz=%"
        $str_d2    = "changetor"
        $str_taunt = "!eatadick"
        $str_anti1 = "dnSpy" fullword
        $str_anti2 = "SandboxieDcomLaunch" fullword

    condition:
        7 of them
}

