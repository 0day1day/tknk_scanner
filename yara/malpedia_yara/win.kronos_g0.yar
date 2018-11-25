rule win_kronos_g0 {
    meta:
        author = "mak"
        malpedia_version = "20170412"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $get_aes_keys = { 80 ?? ?? 5e 75 0E 80 ?? ?? 01 c9 75 07 80 ?? ?? 02 c3 74 03 46 eb e9}
        $kronos = "Kronos"

    condition:
        any of them
}
