rule win_aldibot_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180920"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.aldibot"
    strings:
        $str_hwid    = "/gate.php?hwid="
        $str_pc      = "&pc="
        $str_localip = "&localip="
        $str_winver  = "&winver="
        $str_aldibot = "Aldi Bot"
        $str_l33t    = "I'm too l33t for the fucking AV's"
        $str_stop    = "StopHTTPDDoS"
        $str_steal   = "StealData"
        $str_alditill= "aldibytill7"

    condition:
        5 of them
}
