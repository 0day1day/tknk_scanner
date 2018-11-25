rule win_orcarat_w0 {
    meta:  
        author = "PwC Cyber Threat Operations :: @tlansec"
        info = "removed MZ@0 and filesize to aid memory scanning"
        sha1 = "253a704acd7952677c70e0c2d787791b8359efe2c92a5e77acea028393a85613"
        malpedia_version = "20180930"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $apptype1="application/x-ms-application"
        $apptype2="application/x-ms-xbap"
        $apptype3="application/vnd.ms-xpsdocument"
        $apptype4="application/xaml+xml"
        $apptype5="application/x-shockwave-flash"
        $apptype6="image/pjpeg"
        $err1="Set return time error =   %d!"
        $err2="Set return time   success!"
        $err3="Quit success!"

    condition:
        all of ($apptype*) and 1 of ($err*)
}
