rule win_gaudox_a0 {
    meta:
        author = "Slavo Greminger"
        date = "20170327,20171113"
        malpedia_version = "20171121"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $loader1 = "\\ntdll.dll" wide
        $loader2 = "%02X%02X%02X%02X%02X%02X%02X%02X"
        $loader3 = "hdr=CLNT"
        $loader4 = "&%s=%u"
        $loader5 = "&%s=%s"
        $loader6 = "&%s=%ls"
        $loader7 = "hdr=%s&tid=%s&cid=%s&trs=%i"

        $ops_getrc4_1a = { 6A 2D  6A 00  E8 [4]  85 C0  7? ??  0F B6 05 }
        $ops_getrc4_1b = { 0F B6 05 [4]  B9 ?? 00 00 00  8? [1-4]  0F 45 C1  A2 [4]  33 C0 } 
        $ops_getrc4_2  = { A1 [4]  A3 [4]  A1 [4]  A3 [4]  A1 [4]  6A 04  A3 [4]  A1 [4]  68 00 30 00 00 } 
    condition:
        5 of them
}
