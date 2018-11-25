rule win_billgates_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171223"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $bg1a    = "UpdateBill"
        $bg1b    = "BillStatus"
        $bg2     = "UpdateGates"

        $attack1 = "CAttackBase"
        $attack2 = "CAttackUdp"
        $attack3 = "CAttackSyn"
        $attack4 = "CAttackIcmp"
        $attack5 = "CAttackDns"
        $attack6 = "CAttackAmp"

        $misc1   = "xpacket.ko"
        $misc2   = "MainBeikong"
        $misc3   = "MainBackdoor"
        $misc4   = "MainSystool"
        $misc5   = "MainMonitor"
        $misc6   = "/usr/bin/pythno"

        $str_1   = "%s:%d:%d:%d:%d:%s"
        $str_2   = "2|%s|1|%s|%d|1|15|5|%d|"
        $str_3   = ":task_list"
        $str_4   = ":link_list"
        $str_5   = "DNSSupport"

        $svch0st = "svch0st.exe"

    condition:
        ((any of ($bg*) and 8 of them) or (3 of ($str_*))) and $svch0st
}
