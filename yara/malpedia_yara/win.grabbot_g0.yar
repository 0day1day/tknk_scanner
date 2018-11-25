rule win_grabbot_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170821"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_form1 = "%s: %s:%s::%s:%u " wide
        $str_ssdat  = "%s%s.dat" wide
        $str_ssidat  = "%s%s%i.dat"

        // This string obfuscation technique is also used by Godzilla Loader
        // $op_strexe    = { (6A 2E  66 89 45 ?? | 6A 2E) 58  (6A 65  66 89 45 ?? | 66 89 45 ?? 6A 65) 58  (6A 78  66 89 45 ?? | 66 89 45 ?? 6A 78) 58  (6A 65  66 89 45 ?? | 66 89 45 ?? 6A 65) 58}
        // $op_strdat    = { (6A 2E  66 89 45 ?? | 6A 2E) 58  (6A 64  66 89 45 ?? | 66 89 45 ?? 6A 64) 58  (6A 61  66 89 45 ?? | 66 89 45 ?? 6A 61) 58  (6A 74  66 89 45 ?? | 66 89 45 ?? 6A 74) 58}
        $op_str_global   = { 6A 47 58 6A 6C 66 89 45 ??  58 6A 6F 66 89 45 ??  58 6A 62 66 89 45 ??  58 6A 61 66 89 45 ??  58 6A 6C 66 89 45 ??  58 6A 5C 66 89 45 ?? }
        $op_str_svchost  = { 6A 5C 58 6A 73 66 89 45 ??  58 6A 76 66 89 45 ??  58 6A 63 66 89 45 ??  58 6A 68 66 89 45 ??  58 6A 6F 66 89 45 ??  58 6A 73 66 89 45 ??  58 6A 74 66 89 45 ?? }

        $op_anticheck    = { C7 45 ?? 41 C7 75 41  C7 45 ?? 50 EA 38 E8  C7 45 ?? 01 4A 30 5A  C7 45 ?? 9B F7 1E 6A }
        $op_simplecrypto = { 33 C0  AC  3C 61 7? ?? 2C 20  C1 CF 0D  03 F8  E2 }

    condition:
        all of ($str_*) 
        or (1 of ($str_*) and 1 of ($op_*))
        or 2 of ($op_*)
}

