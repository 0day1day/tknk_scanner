rule win_cobra_w0 {
    meta:
        source = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/#_footnote_2"
        malpedia_version = "20170512"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $s1 = "ModStart"
        $s2 = "ModuleStart"
        $t1 = "STOP|OK"
        $t2 = "STOP|KILL"

    condition:
        (uint16(0) == 0x5a4d) and (1 of ($s*)) and (1 of ($t*))
}
