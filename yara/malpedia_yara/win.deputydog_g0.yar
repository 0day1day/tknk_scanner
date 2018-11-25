rule win_deputydog_g0 {
    meta:
        author = "FireEye Labs"
        version = "1.0"
        description = "detects string seen in samples used in 2013-3893 0day attacks"
        reference = "8aba4b5184072f2a50cbc5ecfe326701"
        malpedia_version = "20150521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $a = "DGGYDSYRL"
        
    condition:
        $a
}
