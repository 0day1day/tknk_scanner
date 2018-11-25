rule win_gameover_dga_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de"
        date = "2014-07-15"
        description = "2014-07-15 New GameOver Zeus with DGA"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        // these mutexes seem to be unique to the GameOver family
        $mutex_main_a = { 7B 34 89 87 }
        $mutex_main_b = { 3F 53 43 2A }
        
        $dga_seed_1 = { 01 05 19 35 }
        $dga_seed_2 = { 45 e6 52 00 }
        
        // DGA uses 4 domains
        $dga_instr_com = { C7 04 33 63 6f 6d 00 }
        $dga_instr_org = { C7 04 33 6F 72 67 00 }
        $dga_instr_biz = { C7 04 33 62 69 7a 00 }
        $dga_instr_net = { C7 04 33 6E 65 74 00 }
        
        // core pieces of the DGA
        $prepare_hash_magic = { C7 45 ?? ?? ?? ?? ?? 50 8D 4D ?? E8 }
        $divide_by_36 = { 6A 24 59 F7 F1}
        $invert_string = { 8A 0F 8A 16 88 0E 4E 88 17 47 3B FE }
        
    condition:
        ($mutex_main_a or $mutex_main_b) and (3 of ($dga_instr_biz, $dga_instr_org, $dga_instr_net, $dga_instr_com)) and (1 of ($dga_seed_*)) and ($prepare_hash_magic and $divide_by_36 and $invert_string)
}
