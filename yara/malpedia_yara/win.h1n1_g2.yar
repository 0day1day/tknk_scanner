rule win_h1n1_g2 {
    meta:
        author = "mak"
        module = "h1n1"	
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $upack  = "UpackByDwing"
        $decode_xors = { EB ??  33 C0 (2D | 35 | 05) [4] AB (2D | 35 | 05) [4] AB (2D | 35 | 05) [4] AB }
    condition:
        all of them
}
