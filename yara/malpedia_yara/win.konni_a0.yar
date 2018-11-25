rule win_konni_a0 {
    meta:
        author = "CCIRC"
        description = "Yara rule for Konni RAT"
        revision = 1
        date = "2018-03-07"
        md5 = "38ead1e8ffd5b357e879d7cb8f467508"
        malpedia_version = "20170809"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"
    strings:
        $ocx_string1 = "%s\\solhelp.ocx"
        $string1 = "/uploadtm.php"
        $string2 = "/upload.php"
        $string3 = "/download.php?file=%s_dropcom"
        $string4 = "id=%s&time=%s&title=%s %s&passwd=%s"
        $string5 = "id=%s&title=%s %s&passwd=%s"
        $string6 = "id=%s&passwd="
        $string7 = "POST http://%s/login.php"
        $string8 = "InstallDate"
    condition:
        4 of them
}
