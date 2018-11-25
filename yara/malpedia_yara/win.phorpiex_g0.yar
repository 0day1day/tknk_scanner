rule win_phorpiex_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180716"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phorpiex"
    strings:
        $str_trik_pdb  = "Trik.pdb" 
        $str_physical  = "\\\\.\\PhysicalDrive0"
        $str_zone      = "%s:Zone.Identifier"
        $str_zone_w    = "%ls:Zone.Identifier" wide
        $str_enabled   = "%s:*:Enabled:%s"
        $str_enabled_w = "%ls:*:Enabled:%s" wide
        $str_NICKJOIN  = "NICK\x00\x00\x00\x00JOIN" fullword
        $str_PRIVMSG    = "PRIVMSG" fullword

        $op_c2_port_14  = { 8D 04 ??   03 C0  0F B7 [0-1] [4] 00  (03 C0  8B [0-1] [4] 00 | 8B [0-1] [4] 00  03 C0 ) [0-1] 5? E8 }
        $op_c2_port_16 = {                   0F B7 [0-1] [4] 00  (5?  8B 55 FC| 03 C0)  (6B ?? 0C  8B |8B ) [0-1] [4] 00  5? } 
        $op_c2_2014     = { 33 ??  8D 04 ??  83 3C 85 [4] 00  75 02  33 ?? } 
        $op_c2_2016     = { 8B 4D FC  [0-3]  83 [1-2] [4] 00  7? (0?|1?)  C7 45 FC 00 00 00 00  8B 55 F0  83 C2 01 } 
        $op_prng        = { E8 [4]  99  B9 0D 00 00 00  F7 F9  83 C2 03  89 55 08 }
      
    condition:
        3 of ($str_*) and 1 of ($op_*)
}
