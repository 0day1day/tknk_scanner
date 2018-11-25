rule win_backswap_g0 { 
    meta: 
        description = "BackSwap trojan"
        date = "2018-05-25"
        author = "Dawid Osojca"
        reference = "https://www.welivesecurity.com/2018/05/25/backswap-malware-empty-bank-accounts/"
        md5 = "9265720139aa08e688d438d0d8e48c9e"
        /* b2076cda88f44eacc95b21a741b9a759 03694e2fa1744fb856e652667d4801fb */
        malpedia_version = "20180528"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backswap"
    strings: 
        $cmd1 = "/V:ON /C dir /S/B/A-D \"%APPDATA%\\Mozilla\\prefs.js\" > \"%TEMP%"
        $cmd2 = "echo ^user_pref(\"devtools.selfxss.count\", 100); >> \"!v!\""
        $s1 = "Chrome_WidgetWin_1"
        $s2 = "MozillaWindowClass"
        $s3 = "TabThumbnailWindow"
    condition: 
        any of ($cmd*) and any of ($s*)
}
