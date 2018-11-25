rule win_computrace_w0 {
    meta:
        description = "Absolute Computrace Agent Executable"
        reference = "https://asert.arbornetworks.com/lojack-becomes-a-double-agent/#Yara"
        malpedia_version = "20180503"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $a = { D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04 }
        $b1 = { 72 70 63 6E 65 74 70 2E 65 78 65 00 72 70 63 6E 65 74 70 00 }
        $b2 = { 54 61 67 49 64 00 }
    condition:
        $a or ($b1 and $b2)
}
