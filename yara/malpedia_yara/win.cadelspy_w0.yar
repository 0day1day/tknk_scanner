rule win_cadelspy_w0 {
    meta:
        source = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = { 
                56 57 8B F8 8B F1 33 C0 3B F0 74 22 39 44 24 0C
                74 18 0F B7 0F 66 3B C8 74 10 66 89 0A 42 42 47
                47 4E FF 4C 24 0C 3B F0 75 E2 3B F0 75 07 4A 4A
                B8 7A 00 07 80 33 C9 5F 66 89 0A 5E C2 04 00
              }
        $s2 = "ntsvc32"
        $s3 = "ntbind32"
    condition:
        $s1 and ($s2 or $s3)
}
