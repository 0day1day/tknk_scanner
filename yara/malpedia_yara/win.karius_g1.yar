rule win_karius_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "proxy module"
        malpedia_version = "20180614"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_dll32_0 = "proxy_dll32.dll"
        $str_dll32_1 = "proxy32.dll"
        $str_dll64_0 = "proxy_dll64.dll"
        $str_dll64_1 = "proxy64.dll"
        $str_refl    = "ReflectiveLoader"
        $str_config0 = "--disable-http2" wide
        $str_config1 = "--disable-http2 --disable-quic" wide
        $str_AP32    = "AP32\x18\x00"

    condition:
        4 of them
}
