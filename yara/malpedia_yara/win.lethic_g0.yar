rule win_lethic_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        kudos = "Vitali Kremez"
        malpedia_version = "20171110"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        // anti checks dropper
        $str_per1   = "RECYCLER\\" wide
        $str_check1 = "wine_get_version"
        $str_check2 = "Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" 
        $str_check3 = "VideoBiosVersion"
        $str_check4 = "SystemBiosVersion"
        $str_check5= "\\\\.\\VBoxGuest" wide

        $ops_calls_connect = { 6A 10  8D ?? [4]  5?  8B ?? [4]  8B ?? [4]  5?  8B ?? [4]  8B ?? [4]  FF (D0|D1|D2)  83 F8 FF }
        $ops_calls_ioctl   = { 5?  68 [4]  8B ?? [4]  8B ?? [4]  5?  8B ?? [4]  8B ?? [4]  FF (D0|D1|D2)  83 F8 FF }
        $ops_calls_send    = { 5?  8B ?? ??  5?  8B 45 08  8B ?? [4]  FF (D0|D1|D2)  89 }
        $ops_calls_mutex   = { 8B ?? [4]  8B ?? [4]  5?  6A 00  6A 00  8B ?? [4]  8B ?? [4]  FF (D0|D1|D2)  89 }
        $ops_calls_move    = { 5?  8B ?? ??  81 ?? 08 02 00 00  5?  8B ?? ??  8B ?? [4]  FF (D0|D1|D2)  89 }

    condition:
        (3 of ($str_*) and any of ($ops_*)) or 3 of ($ops_*)
}
