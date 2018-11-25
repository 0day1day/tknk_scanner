rule win_h1n1_g0 {
    meta:
        author = "mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $encode_domains = { 97 33 C0 (2D | 35 | 05) [4] AB (2D | 35 | 05) [4] AB (2D | 35 | 05) }
        $rc4_size = "RC4-Size: "
        $url0 = "guid=%.8X%.8X&os=%d&bits=%d&pl=%d"
        $url1 = "guid=%.8X%.8X&report="
        $url2 = "x_guid=%.8X%.8X&x_os=%d&x_bits=%d&x_pl=%d"
        $url3 = "x_guid=%.8X%.8X&x_report="

    condition:
        $encode_domains and (2 of ($url*) or $rc4_size)
}
