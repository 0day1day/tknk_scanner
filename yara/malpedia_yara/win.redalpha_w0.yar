rule win_redalpha_w0 {
    meta:
        desc = "RedAlpha 2017 Campaign, Dropper"
        author = "JAG-S, Insikt Group, RecordedFuture"
        TLP = "White"
        source = "https://www.recordedfuture.com/redalpha-cyber-campaigns/"
        md5_x86 = "cb71f3b4f08eba58857532ac90bac77d"
        md5_x64 = "1412102eda0c2e5a5a85cb193dbb1524"
        malpedia_version = "20180706"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $drops1 = "http://doc.internetdocss.com/nethelp x86.dll" ascii wide
        $drops2 = "http://doc.internetdocss.com/audio x86.exe" ascii wide
        $drops3 = "http://doc.internetdocss.com/nethelp x64.dll" ascii wide
        $drops4 = "http://doc.internetdocss.com/audio x64.exe" ascii wide
        $source1 = "http://doc.internetdocss.com/word x86.exe" ascii wide
        $source2 = "http://doc.internetdocss.com/word x64.exe" ascii wide 
        $path1 = "\\Programs\\Startup\\audio.exe" ascii wide
        $path2 = "c:\\Windows\\nethelp.dll" ascii wide
        $persistence1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\svchost" ascii wide
        $persistence2 = "%SystemRoot%\\system32\\svchost.exe -k " ascii wide
        $persistence3 = "SYSTEM\\CurrentControlSet\\Services\\" ascii wide
        $persistence4 = "Parameters" ascii wide
        $persistence5 = "ServiceDll" ascii wide
        $persistence6 = "NetHelp" ascii wide
        $persistence7 = "Windows Internet Help" ascii wide
    condition:
    ( any of ($drops*) or any of ($source*) or any of ($path*) or 6 of ($persistence*) )
}
