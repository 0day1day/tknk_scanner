rule win_tdtess_w0 {
    meta:
        description = "Detects malicious service used in Operation Wilted Tulip"
        author = "Florian Roth"
        reference = "http://www.clearskysec.com/tulip"
        date = "2017-07-23"
        hash1 = "3fd28b9d1f26bd0cee16a167184c9f4a22fd829454fd89349f2962548f70dc34"
        malpedia_version = "20170914"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "d2lubG9naW4k" fullword wide /* base64 encoded string 'winlogin$' */
        $x2 = "C:\\Users\\admin\\Documents\\visual studio 2015\\Projects\\Export\\TDTESS_ShortOne\\WinService Template\\" ascii

        $s1 = "\\WinService Template\\obj\\x64\\x64\\winlogin" ascii
        $s2 = "winlogin.exe" fullword wide
    condition:
        filesize < 200KB and ( 1 of ($x*) or 2 of them )
}

