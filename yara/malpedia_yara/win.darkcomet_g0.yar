rule win_darkcomet_g0 {
    meta:
        author = "Kevin Breen / Jean-Philippe Teissier /  botherder / Florian Roth / David Cannings / Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180124"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    //  Prone to FP:
    // AVICAP32.DLL                  // Alusinus v0.9, Nuclear RAT 2.1.0
    // IDispatch4                    // Alusinus v0.9,
    // FastMM Borland Edition        // Insidious 1.x, Nuclear RAT 2.1.0, Restorator 2007 v3.70, Syndrome RAT v4.3.1
    // %s, ClassID: %s               // Insidious 1.x, Nuclear RAT 2.1.0, Restorator 2007 v3.70, Syndrome RAT v4.3.1
    // DCDATA                        // Darkback, Indetectable RAT

    strings:
        // all versions
        $str_vA_b1   = "#BOT#" wide ascii
        $str_vA_d1   = "DOSHTTPFLOOD" wide ascii
        $str_vA_k1   = "ctiveOnlineKey" wide ascii
        $str_vA_k2   = "ctiveOfflineKey" wide ascii
        $str_vA_m1   = "[<-]"
        $str_vA_m2   = "Command successfully executed!"
        $str_vA_m4   = "GENCODE" wide
        $str_vA_m5   = "NETDATA" wide
        $str_vA_m6   = "GetSIN" wide
        $str_vA_m7a  = "#SendTaskMgr"
        $str_vA_m7b  = "#RemoteScreenSize"
        $str_vA_m8   = "infoes"
        $str_vA_c1   = "#BEGIN DARKCOMET DATA --"
        // special Versions
        $str_vX_m1   = "DarkO\\_2" wide ascii
        // v2.x
        $str_v2_m1   = "MUTEXNAME" wide // M\x00U\x00T\x00E\x00X\x00N\x00A\x00M\x00E\x00
        // v3.x, v4.x
        $str_v34_m3  = "CLOSECAM"
        // v3.x, v4.x, v5.x
        $str_v345_m1 = "#KCMDDC"
        $str_v345_m2 = "DC_MUTEX-"
        $str_v345_m3 = "I wasn't able to open the hosts file"
        // v5.x
        $str_v5_m1   = "WEBCAMSTOP"
        $str_v5_m2   = "ping 127.0.0.1 -n 4 > NUL &&"
        $str_v5_s1   = "ACTIVEREMOTESHELL" wide ascii

    condition:
        3 of them
}

