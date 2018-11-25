rule win_9002_w0 {
    meta:
        author = "FireEye Labs"
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        
    strings:
        $a = "rat_UnInstall" wide ascii
        
    condition:
        $a
}
