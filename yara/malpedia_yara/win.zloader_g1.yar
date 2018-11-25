rule win_zloader_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        kudos = "CCIRC Akira"
        malpedia_version = "20170620"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $string1 = "_Run@4"
        $string2 = "shared_%s"
        $string3 = "LdrLoadDll"
        $string4 = "CreateRemoteThread"
        $string5 = "_Start@4"
        $string6 = "payload.dll"
        $string7 = "/ppp/a1.php"
        $string8 = "%x%x%x%x%x%x%x"
        $string9 = "bcdfghklmnpqrstvwxzaeiouy%x%x%x%x%x%x"
        $string10 = "Software\\Microsoft\\%s"
        $string11 = "ObtainUserAgentString\x00*/*\x00"
        $string12 = "RROR\x00VM is not supported.\x00"

        $ops_openReg   = { 3F 00 0F 00 [1-4] 00 00 00 00 [1-4] 01 00 00 80  FF 15 [4]  83 EC 14  89 84 24 ?? 04 00 00  B8 }
        $ops_storeReg1 = { E0 02 00 00 [4-10] 02 01 00 00 }
        $ops_storeReg2 = { 02 01 00 00 E8 [4-30] E0 02 00 00 }
        $ops_storeReg3 = { E0 02 00 00 E8 [4-18] E0 02 00 00 }
        $ops_callHttpSend = { 8B [2] 89 [3] 89 [2] FF 15 [4]  83 EC 14  (85 C0 [0-5] B9 | B9 [4-9] 85 C0) }
        $ops_callInternetRead = { 89 [3] 8B [2] 89 [2] FF 15 [4]  83 EC 10  [0-3] 85 C0  B8 [4] B9 [4] 0F 45 C1 }

    condition:
        3 of ($string*) and 1 of ($ops_*)
}
