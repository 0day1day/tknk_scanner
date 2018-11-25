rule win_nanocore_w0 {
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/NanoCore"
        maltype = "Remote Access Trojan"
        filetype = "exe"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/NanoCore.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $a = "NanoCore"
        $b = "ClientPlugin"
        $c = "ProjectData"
        $d = "DESCrypto"
        $e = "KeepAlive"
        $f = "IPNETROW"
        $g = "LogClientMessage"
		$h = "|ClientHost"
		$i = "get_Connected"
		$j = "#=q"
        $key = {43 6f 24 cb 95 30 38 39}


    condition:
        6 of them
}
