rule win_rovnix_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "Targets the loader"
        malpedia_version = "20170628"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $str_0 = "{%08X-%04X-%04X-%04X-%08X%04X}"
        $str_1 = "NTFS"
        $str_2 = "\\??\\PHYSICALDRIVE0" wide
        $str_3 = "\\Device\\Harddisk0\\Partition%u" wide
        $str_4 = "VBR" wide
        $str_5 = "BkInstall"
        $str_aplib = "by Joergen Ibsen, All Rights Reserved"

        $un_joiner_header = { (46 4A|4A 31) (10|00) 00 00 [10-14] ?? (46 4A|4A 31) (10|00) 00 00 }
        $un_op_CreateMagic1 = { (80 3C 3?|83 F?) 33  (74|75) ??  [0-6] 81 (3C 3?|3A) 33 33 33 33 (74|75) }
        $un_op_UAC_1 = { 6A 0? [0-3] (5?|6A 00) (FF 15|E8) [4] [0-3] C7 45 ?? 3C 00 00 00 C7 45 [4-6] 8? ?? ??  8? ?? ??  (50 FF 15|C7 45) }
        $un_op_UAC_2 = { 6A ?? 8D 45 ?? 5?  FF 15 [4] C7 45 ?? 3C 00 00 00   [0-18]   C7 45 ?? [4] FF 15 }

    condition:
        filesize < 200KB and 4 of ($str_*) and any of ($un_*)
}
