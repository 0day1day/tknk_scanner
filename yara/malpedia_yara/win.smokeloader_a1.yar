rule win_smokeloader_a1 {
    meta: 
        author = "pnx"
        info = "created with malpedia YARA rule editor"
        malpedia_version = "20171001"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"
    strings:
        // 2012 smokeloader's recognizable entry point - pro-tip: don't code in asm :)
        $string = { e8 00 00 00 00 5b 83 eb 05 31 c9 }
    condition:
        all of them
}
