rule win_reactorbot_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        comment = "This dropper almost always includes the rovnix loader. Exception: 47abcdf58fbff91f9465517b96ea13d3"
        malpedia_version = "20170630"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $str_1 = "%d.%d [%d,%d]" wide
        $str_2 = "\"%s\" -q -n \"%s\" %u" wide
        $str_3 = "%02d.%02d.%d" wide
        $str_4 = "%02d:%02d:%02d" wide
        $str_5 = "\"%s\" %d EVT%u" wide
//        $op_isWow64 = { C7 45 FC 00 00 00 00  68 ?? ?? 4? 00  68 ?? ?? 4? 00  FF 15 [4] 50 FF 15 [4] A3 ?? ?? 4? 00 83 3D ?? ?? 4? 00 00  7? }
        $op_isWow64g = { C7 45 FC 00 00 00 00  68 [4]  68 [4]  FF 15 [4] 50 FF 15 [4] A3 [4] 83 3D [4] 00  7? }
//        $op_obfs1a  = { 68 FF FF FF 7F 8D 45 0C 50 D1 EE 56 57 E8 }
//        $op_obfs1b  = { 66 89 30 83 C0 02 49 4A 7? ?? 83 E8 02 5B B9 7A 00 07 80 5F 66 89 10 } 
        $op_obfs1g  = { 5?  B? 7A 00 07 80 [0-2] 5F [0-3] 8B C? 5? [0-2] 5?  C2 ?? 00  85 D2 75 1?} 
        $op_cs2     = { 5E 5D C2 0C 00 B8 57 00 07 80  85 F6  7? ??  C7 06 00 00 00 00 5E 5D C2 0C 00 } 
//        $op_compVBR = { 6A 00 6A 00 FF 15 [4] A3 [4] 68 10 27 00 00 8B 15 [4] 52 FF 15 }
        $op_compVBRg = { 6A 00 6A 00 FF 15 [4] (A3 [3] ?? |8? [2-3] 8? [2-3] 7? ??) 68 10 27 00 00 8B [2-5] 5? FF 15 }
        $op_bin     = { 50 68 24 08 00 00 68 [4] E8 [4] 89 45 FC 83 ?? ?? 00 7? ?? 6A 14 }
// shared with reactorbot_loader
        $op_obfs2a  = { 83 C0 01  89 45 FC  8B 4D FC  3B 4D 0C 7? ??  0F B7 55 10 8B 45 FC 8B 4D 08 0F B7 04 41 33 C2 }
        $op_obfs2b  = { 0F B7 04 41  33 C2  8B 4D FC  8B 55 08  66 89 04 4A  E? ?? }
    condition:
        (3 of ($str_*) and 3 of ($op_*)) 
}

