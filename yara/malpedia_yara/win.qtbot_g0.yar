rule win_qtbot_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171105"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $ops_createMutexName = { 83 E8 01  7? ?? 48  83 E8 01  7? ??  48  83 E8 01 7? ??  6A 2D 5? }
        $ops_keyboardLayout = { 25 FF 03 00 00  83 C0 E8  83 F8 2B  77 11  0F B6 80 [4] FF 24 85 }
        $ops_rc4strings = { 8B 45 08  6A 02  8B 0C 85 [4]  8B 01  03 C0  50  8D 41 04  50  E8 }
        $ops_callRC4key = { 5?  6A 30  5?  6A 20  68 [4]  89 46 2C  E8 [4]  6A 0? }

    condition:
        2 of them
}
