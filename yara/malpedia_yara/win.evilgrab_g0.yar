rule win_evilgrab_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        date = "2017-08-04"
        malpedia_version = "20170804"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $format_0 = "%c%s|(%s)|%d|%s|%s|%s|%s|%s|%s|%s|%d|%d|%x|%x|%s|"
        $format_1 = "4%.4d-%.2d-%.2d %.2d:%.2d:%.2d"
        $format_2 = "2%.4d-%.2d-%.2d %.2d:%.2d:%.2d"
        
        $targets_0 = "Outlook2003_IMAP"
        $targets_1 = "Outlook2002_IMAP"
        $targets_2 = "OutLook_HTTP"
        $targets_3 = "IE7_AutoComplete"
        

    condition:
        (2 of ($format_*)) and (3 of ($targets_*))
}
