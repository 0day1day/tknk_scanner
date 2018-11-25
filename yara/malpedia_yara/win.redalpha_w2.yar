rule win_redalpha_w2 {
    meta:
        author = "JAG-S, Insikt Group, Recorded Future"
        tlp = "White"
        source = "https://www.recordedfuture.com/redalpha-cyber-campaigns/"
        md5 = "e6c0ac26b473d1e0fa9f74fdf1d01af8"
        md5 = "e28db08b2326a34958f00d68dfb034b0"
        md5 = "c94a39d58450b81087b4f1f5fd304add"
        md5 = "3a2b1a98c0a31ed32759f48df34b4bc8"
        desc = "RedAlpha Dropper"
        version = "1.0"
        malpedia_version = "20180706"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $cnc = "http://doc.internetdocss.com/index?"
    condition:
        all of them
}
