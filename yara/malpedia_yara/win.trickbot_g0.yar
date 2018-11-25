rule win_trickbot_g0 {
    meta:
        author   = "mak"
        function = "ldr_get_binary"
        module   = "trickbot"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $r0 = "IDR_X86BOT" fullword wide
        $r1 = "IDR_X64BOT" fullword wide
        $r2 = "IDR_X64LOADER" fullword wide
    
    condition:
    all of them
}
