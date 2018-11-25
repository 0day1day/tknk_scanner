rule win_jimmy_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        reference = "https://securelist.com/jimmy-nukebot-from-neutrino-with-love/81667/"
        malpedia_version = "20170926"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $op_rc4 = { 55  8B ??  83 ?? ??  C6 ?? ?? ??  6A ??  68 [4]  E8 [3] (?? | ?? 59 59 ) 89 45  } 
        $op_checksum = { 8B 45 08  03 45 F8  0F BE 00  33 45 FC  89 45 FC  8B 45 FC  69 C0 [4]  89 45 FC  EB C? }

        $op_check_name = { E8 [3] (?? | ??  59)  89 45 F4  83 7D F4 28  7? ??  83 7D F4 40  7? ??  83 7D F4 20  7? ??  C6 45 ?? 01 }
        $op_check_cpuid_xorconst = { 83 7D ?? 06  7? ??  8B 45 ??  8B 4? ?? ??  (35 [3] ??|83 F0 ??)  39 45 FC }

    condition:
        2 of them
}

