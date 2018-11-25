rule win_locky_g0 {
    meta:
        author = "mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $note0 = "_Locky_recover_instructions.txt" fullword wide
        $note1 = "\\_Locky_recover_instructions.txt" fullword wide

        /* this wont work, they change it to offten
        $ext0   = ".locky" fullword wide
        $ext1   = ".zepto" fullword wide */

        $cfg_sig  = {  F1 42 A1 FD DC D1 78 BB }
        $cfg_check = {81 ?? 8D DD BB 88 39 ?? 04 75 0B 81 ?? B2 A2 BC DD 39 ?? 08}
        $dga_tld = { 69 C0 E1 24 19 B1 C1 C8 07 03 C3 6A 0A}
        $random_chars = "0123456789ABCDEF" fullword wide
        
    condition:
        any of ($note*) and
        ($cfg_sig or $cfg_check)  and ($dga_tld or $random_chars)
}
