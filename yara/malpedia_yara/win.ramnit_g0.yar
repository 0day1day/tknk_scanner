rule win_ramnit_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        internal = "275629"
        malpedia_version = "20170308"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $mutex = "{%08X-%04X-%04X-%04X-%08X%04X}"
        $createMutex = { 6A (00|01) (6A 00|FF 7? ??) E8 [4] 89 4? ?? 0B C0 74 ?? E8 [4] 3D B7 00 00 00 75 }
        $copyFile = { 6A 00 (FF 7? ??|68 [3] ??) (FF 7? ??|68 [3] ??) E8 ?? ?? 00 00 0B C0 7? }

        $hex_reg = /\x03\x55\x08[\x90]*\x6a\x19[\x90]*\x52[\x90]*\xE8[\S\s]{4}[\x90]*\x04\x61[\x90]*\x88\x06[\x90]*\x46/

        $dga = { 83 F? 12 [0-24] 6A 19 [0-8] 5? [0-8] E8 [4] [0-8] 04 61 }

    condition:
        2 of them
}
