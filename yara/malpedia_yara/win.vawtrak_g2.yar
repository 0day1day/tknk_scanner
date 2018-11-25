rule win_vawtrak_g2 {
    meta:
        author = "kalmar"
        module = "vawtrak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $sh_get_cfg = { 69 ?? ?? 6D 4E C6 41 ??  39 30 }
    condition:
        $sh_get_cfg and uint16(uint32(8)) == 0x5a4d
}
