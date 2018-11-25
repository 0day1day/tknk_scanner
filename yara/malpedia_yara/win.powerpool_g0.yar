rule win_powerpool_g0 {
    meta:
        description = "Identify potential PowerPool malware stage 1"
        author = "blevene @upperCase, Chronicle Security"
        version = "1.0"
        date = "09-06-2018"
        TLP = "GREEN"
        reference = "https://www.welivesecurity.com/2018/09/05/powerpool-malware-exploits-zero-day-vulnerability/"
        hash = "8c2e729bc086921062e214b7e4c9c4ddf324a0fa53b4ed106f1341cfe8274fe4"
        malpedia_version = "20180907"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        //unique strings
        $s1 = "Cookie: SESSION=" ascii
        $s2 = "reconnect" ascii
        $s3 = "proc_kill" ascii
        $s4 = "file_exec" ascii
        $s5 = "file_del" ascii
        $s6 = "proxy.log" ascii
        $s7 = "?id=%s&info=%s" wide // this might be strong enough on its own?
        $s8 = "rar.exe a -r %s.rar -ta" wide
        $s9 = "powershell.exe $PSVersionTable.PSVersion >" wide

        
        //interesting mutex
        $m1 = "MyDemonMutex%d" wide

    condition:
        (4 of ($s*) or $m1)
}
