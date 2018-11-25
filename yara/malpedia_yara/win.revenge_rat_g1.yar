rule win_revenge_rat_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180122"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $stub_v01_m           = "||XX||SS||XX||SS||" wide

        $stub_v01_v02_s1a     = "[MessgboxFakeCheck]" wide
        // note: also in Comet RAT
        $stub_v01_v02_c1      = "SCHTASKS /Delete /TN" wide

        $stub_v01_v03_m1      = "Ready to any command!" wide
        $stub_v01_v03_m2      = "ScriptWirte" wide

        $stub_v02_v03_m3      = "v_B01" wide

    condition:
        3 of them
}
