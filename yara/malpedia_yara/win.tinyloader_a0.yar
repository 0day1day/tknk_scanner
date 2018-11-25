rule win_tinyloader_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180417"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $op_loadget1 = { 6A 04  68 00 30 00 00  68 00 14 00 00  6A 00  FF 15 [4]  89 C5  8D 4D ??  8D 55 ??  A1 [4]  8B 1D } 
        $op_loadget2 = { 6A 40  68 00 30 00 00  68 00 80 02 00  6A 00  FF 15 [4-32]  8B 1D [4-32]  05 00 40 01 00 }
        $op_dword    = { 05 00 40 01 00  [0-2]  31 DB  [0-2]  8B BB [4]  [0-2]  89 38  [0-2]  81 FB [2] 00 00  [0-2]  7? ??  [0-2]  83 C0 04  [0-2]  83 C3 04 } 
        $op_loadget2_64 = { 48 C7 C1 00 00 00 00  48 C7 C2 00 80 02 00   49 C7 C0 00 30 00 00   49 C7 C1 40 00 00 00    FF 15  }
        $op_dword_64    = { 05 00 40 01 00  [0-2]  48 31 DB  [0-2]  67 8B BB [4]  [0-2]  89 38  [0-2]  81 FB [2] 00 00  [0-2]  7? ??  [0-2]  48 83 C0 04  [0-2]  83 C3 04 } 
    condition:
        any of them
}
