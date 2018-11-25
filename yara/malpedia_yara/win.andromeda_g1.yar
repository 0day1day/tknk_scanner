rule win_andromeda_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170612"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $blacklisted1 = { 32 44 DD 99 B4 9D 85 2D }
        $blacklisted2 = { CE 0D 34 64 74 44 C5 63 }
        $blacklisted3 = { 8B 9C 9C 34 CE EB 46 34 }
        $blacklisted4 = { FE B1 A9 5B F3 BE E2 3C }
        $blacklisted5 = { 2B F0 46 3D F7 10 AE 77 }
        $blacklisted6 = { 5D E9 44 F3 6F 6D BE 2D }
        $blacklisted7 = { 44 02 D1 A3 91 ED 72 1D }
        $blacklisted8 = { BE 6B 93 96 58 DF 8C 27 }
        $blacklisted9 = { 85 F8 FF 3B D9 23 33 6D }

    condition:
        4 of ($blacklisted*)
}
