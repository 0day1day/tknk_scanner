rule win_trickbot_w1 {
    meta:
        description = "Trickbot Socks5 bckconnect module"
        author = "@VK_Intel"
        reference = "Detects the unpacked Trickbot backconnect in memory"
        date = "2017-11-19"
        hash = "f2428d5ff8c93500da92f90154eebdf0"
        source = "http://www.vkremez.com/2017/11/lets-learn-trickbot-socks5-backconnect.html"
        malpedia_version = "20171214"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s0 = "socks5dll.dll" fullword ascii
        $s1 = "auth_login" fullword ascii
        $s2 = "auth_ip" fullword ascii
        $s3 = "connect" fullword ascii
        $s4 = "auth_ip" fullword ascii
        $s5 = "auth_pass" fullword ascii
        $s6 = "thread.entry_event" fullword ascii
        $s7 = "thread.exit_event" fullword ascii
        $s8 = "</moduleconfig>" fullword ascii
        $s9 = "<moduleconfig>" fullword ascii
        $s10 = "<autostart>yes</autostart>" fullword ascii
    condition:
        all of them
}
