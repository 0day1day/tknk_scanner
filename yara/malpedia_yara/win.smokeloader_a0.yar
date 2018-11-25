rule win_smokeloader_a0 {
     meta:
        author = "Slavo Greminger, SWITCH-CERT / Raashid Bhatt / pnx"
        info = "2015 version"
        malpedia_version = "20170714"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"
  
     strings:
        $fmt_string1 = "%d#%s#%s#%d.%d#%d#%d#%d#%d#%s"
        $fmt_string2 = "%d#%s#%s#%d.%d#%d#%d#%d#%d#%d"

        $op_fetch_cnc_url = { 80 3D [4] ?? 76 ?? C6 05 [4] 01 3? ?? A0 [4] 8B }
//        $op_wsprintf_msg  = { A1 [4] 5? A1 [4] 5? 68 [4] 68 [4] 68 [4] [5-12] FF 15 }
        $op_findrc4       = { 53 56 57 8B 7? 0C B? [4] E8 [4] 68 [4] 5? }
        $op_findc2        = { C6 05 [4] 01 33 C0 A0[4] 8B 04 85 [4-6] E8 [4] C3 }

        //pnx
        $op_initial_prologue = { 0f 31 0b 05 ?? ?? ?? ?? c1 d0 02 05 78 56 34 12 19 d0 }

    condition:
        2 of them
}
