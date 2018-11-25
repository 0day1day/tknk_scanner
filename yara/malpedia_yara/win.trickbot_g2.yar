rule win_trickbot_g2 {
    meta:
        author = "mak"
        function = "get_config"
        module = "trickbot"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $m0 = "Global\\TrickBot" fullword wide
        $m1 = "Global\\MGlob" fullword wide
        $m2 = "Global\\VLock" fullword wide
        $s0 = "CONFIG" fullword wide
        $s1 = "/%s/%s/0/%s/%s/%s/%s/%s/" fullword wide
        
    condition:
        1 of ($m*) and 1 of ($s*)
}
