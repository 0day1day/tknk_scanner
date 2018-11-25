rule win_h1n1_g1 {
    meta:
        author = "mak"
        module = "h1n1"	
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        //$prolog = { E8 00 00 00 00 5D 81 ED [4] BB 8E FE 1F 4B E8 }
        $decode_xors = { 97 8b 45 f0 AB (A1 | 2D | 35 | 05) [4] AB (A1 | 2D | 35 | 05) [4] AB }
        
    condition:
        all of them

}
