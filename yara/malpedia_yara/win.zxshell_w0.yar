rule win_zxshell_w0 {
    meta:
        author = "Florian Roth"
        reference = "https://blogs.rsa.com/cat-phishing/"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "zxplug -add" fullword ascii
        $x2 = "getxxx c:\\xyz.dll" fullword ascii
        $x3 = "downfile -d c:\\windows\\update.exe" fullword ascii
        $x4 = "-fromurl http://x.x.x/x.dll" fullword ascii
        $x5 = "ping 127.0.0.1 -n 7&cmd.exe /c net start %s" fullword ascii
        $x6 = "ZXNC -e cmd.exe x.x.x.x" fullword ascii
        $x7 = "(bind a cmdshell)" fullword ascii
        $x8 = "ZXFtpServer 21 20 zx" fullword ascii
        $x9 = "ZXHttpServer" fullword ascii
        $x10 = "c:\\error.htm,.exe|c:\\a.exe,.zip|c:\\b.zip\"" fullword ascii
        $x11 = "c:\\windows\\clipboardlog.txt" fullword ascii
        $x12 = "AntiSniff -a wireshark.exe" fullword ascii
        $x13 = "c:\\windows\\keylog.txt" fullword ascii
    condition:
        3 of them
}
