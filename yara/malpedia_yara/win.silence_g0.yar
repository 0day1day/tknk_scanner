rule win_silence_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "Targets the downloader of win.silence"
        malpedia_version = "20180926"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.silence"
    strings:
        $str_DELETE = "DELETE" fullword
        $op_main3 = {  FF 15 [4]  8B 3D ?? 80 40 00   BE 38 C3 54 00 }
        $op_main4 = {  FF 15 [4]  8B 3D ?? 80 40 00   BE 30 A0 4F 03 }
        $op_strP1 = { 3A D?  74 0?  40  8A 10     84 D?  75 F5         80 38 00  74 0?  46 }
        $op_strP2 = { 3A C?  74 0A  8A 48 01  40  84 C9  75 F4  EB ??  80 38 00  74 0?  8A 5? 01 }
        // silence, mole: RtpEncodePointer
        $op_typo = { C6 45 E8 52  C6 45 E9 74  C6 45 EA 70  C6 45 EB 45  C6 45 EC 6E  C6 45 ED 63 }

    condition:
        2 of them
}
