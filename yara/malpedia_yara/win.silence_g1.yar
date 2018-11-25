rule win_silence_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "Targets the proxy of win.silence"
        malpedia_version = "20180926"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $op_ports = { BA [4] E8 [4]  C7 05 7C AB 41 00 3D 0D 00 00  33 C0  5A 59 59 64 89 10 }

    condition:
        any of them
}
