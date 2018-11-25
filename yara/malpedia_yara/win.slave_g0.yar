rule win_slave_g0 {
    meta:
        author = "mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $ntdl= "__NTDLL_CORE__" fullword wide
        $pbp = "c:\\b\\build\\slave\\win\\build\\src\\third_party\\boringssl\\src\\ssl\\ssl_lib.c"
        $intercnt = { 6A 00 6A 00 6A 03 6A 00 6A 00 6A 50 68 [4] ?? FF 15 }
        $bitcoin = { 6A 23 68 02 20 00 00 FF 15 [4] 8? ?? 56 FF 15 [4] 68 [4] 8? ?? 6A 23 57 E8 }
        
    condition:
        (3 of them)
}
