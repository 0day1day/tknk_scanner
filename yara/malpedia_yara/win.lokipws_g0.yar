rule win_lokipws_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170613"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
//        $ua = "Charon; Inferno"

        $s_0 = "MachineGuid"
        $s_1 = "SOFTWARE\\Microsoft\\Cryptography"
        $s_2 = "last_compatible_version"
        $s_3 = "username_value"
        $s_4 = "password_value"

        $op_memset = {  69 C0 01 01 01 01  5?  8? ?? ?? C1 E? 02  F3 AB  8B ??  83 E1 03  F3 AA }

    condition:
        (all of ($s_*)) and (any of ($op_*))
}
