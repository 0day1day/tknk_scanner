rule win_danabot_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "worker"
        malpedia_version = "20180615"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $str_root      = "root" wide
        $str_dddd      = "%d.%d.%d.%d" wide
        $ops_certroot  = { 74 5D  68 [4]  68 00 00 02 00  6A 00  6A 00  6A 0A  E8 [4]  89 45 EC  83 7D EC 00  0F 95 45 F?  80 7D F? 00  7? ??  6A 00  6A 03 }
        $ops_download1 = { 50  6A 00  FF 15 [4]  A1 [4]  A3 [4]  A1 [4]  03 05 [4]  3B C?  7? 0A  }
        $ops_download2 = { 50  6A 00  FF 15 [4]  A1 [4]  A3 [4]  A1 [4]  03 05 [4]  8B 15 [4]  03 15 [4]  3B C?  7? 0A }
        $ops_genexport = { 64 FF 30  64 89 20   8D 45 E8  50  6A 00  6A 00  6A 08  6A 00   8B 45 F4  50  E8 [4]  85 C0  0F 84 [2] 00 00  B8 00 01 00 00 }
    condition:
        4 of them
}
