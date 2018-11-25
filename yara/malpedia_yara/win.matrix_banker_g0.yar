rule win_matrix_banker_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "loader"
        malpedia_version = "20170816"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_service = "GITSecureService" wide
        $str_mutex = "LoaderMutex"
        $str_binary = "BINARY"
        $strFormat = "[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08p, pX64function=0x%08p, ctx=0x%08p"

    condition:
        3 of them
}

