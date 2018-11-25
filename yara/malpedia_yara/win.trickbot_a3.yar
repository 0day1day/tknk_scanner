rule win_trickbot_a3 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170608, 20171115, 20180418"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $s_1 = "<moduleconfig>*</moduleconfig>"
        $s_2 = "%s%s_configs\\" wide
        $s_3 = "/%s/%s/5/%s/" wide
        $s_4 = "/%s/%s/0/%s/%s/%s/%s/%s/" wide
        $s_5 = "msxml3r.dll" wide

        $op_HEXcreateFile1  = { (6A 20|B? 20 00 00 00)  [1-8] 0F 00 00 80  79 ??  48  83 C8 F0  40  8B ?? ??  (8B ?? ?? 83 | 83) C0 41 }
        $op_HEXcreateFile2  = { 8B ?? ??  83 ?? 41  [5-9]                        66 [2-3] 46  76 ??  B? E9 FF 00 00 }
        $op_HEXcreateFile3  = { 8B ?? ??  83 ?? 41  66 89 04 ??  8B 45 F?  [0-8] 66 [2-3] 46  76 ??  B? E9 FF 00 00 }
        $op_HEXcreateFileN  = { 83 C0 02  66 39 18  75 ??  B? 02 00 00 00  3B C?  76 4?  3B ??  74 ??  83 E8 02  66 83 38 5C }

        $op_CreateMutex1    = { 74 0?  50  FF 15 [4]   83 3? 00  75 0?  6A 01  FF 15 [4] FF 15 [4] 33 ?? 3D B7 00 00 00 0F 94 C? }
        $op_CreateMutex2Obf = { 66 98 42 6? ?? ?? 8? ??  83 C? ??  8? ?? 7? ??  [4-6] 50 6A 01 33 D2 5? 6? ?? ?? FF 15 }
        $op_CreateMutex3    = { 6A 01  FF 15 [4]  (A1|8B 0?) [4]  8B ?? ??  FF D?    33 ??  3D B7 00 00 00  (0F 94 C?|F? D?) }
        $op_CreateMutex4    = { 6A 01  FF 15 [4]  (A1|8B 0?) [4]  FF 50 ??                  ?D B7 00 00 00  (0F 94 C?|F? D?) }

        $op_crypt1          = { 8B 4D F?  8A D1  02 D2  8A C5  C0 F8 04  02 D2  24 03  02 C2 88 45 08 }
        $op_crypt2a         = { C0 F8 04  [0-3]     24 03  [0-2]  8? 45 ??  8? 45 ??  8A ??  C0 F? 02  C0 E? 0?  [0-3]     80 E? 0F }
        $op_crypt2b         = { C0 F8 04  C0 E1 02  24 03  02 C1  88 45 ??  8A 45 ??  8A C8  C0 F9 02  C0 E0 06  02 45 FF  80 E1 0F  C0 E2 04  32 ?? }

        $op_api_crypt       = { 6A 20  5?  8B C?  E8 [4]  85 C0  0F 84 ?? 0? 00 00  8D 45 F4  5?  6A 20  8D 4? 10  5?  8B C?  E8 }
        $op_loadresource    = { 6A 12  5?  E8 [4]  8D 45 F?  5?  8D 4? F?  5?  6A 0A  8D ?? ?? FF FF FF  5? (6A 00 | 5?)  E8 [4]  83 C4 1C }
        $op_init            = { E8 [4]  8D 4E 2C  C7 06 [4]  E8 [4]  33 C0  89 46 14   89 46 10   89 46 1C   89 46 20   89 46 24   89 46 28   89 46 18  8B C6 }

    condition:
        2 of them
}
