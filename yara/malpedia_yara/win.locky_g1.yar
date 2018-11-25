rule win_locky_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        comment = "works on memory dumps / memory strings"
        malpedia_version = "20170810"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $locky_actgethtml = "&act=gethtml&lang="
        $locky_actgettext = "&act=gettext&lang="
        $locky_actaffid   = "&act=getkey&affid="
        $locky_actstats   = "&act=stats&path="
        $locky_actreport  = "&act=report&data="
//        $locky_0F = "0123456789ABCDEF"
//        $locky_val = "FF000000000000FF"
//        $locky_enc = "&encrypted="

        $url_checkupdate = "/checkupdate\x00"
        $url_wikipedia_rsa = "en.wikipedia.org/wiki/RSA_(cryptosystem)"
        $url_wikipedia_aes = "en.wikipedia.org/wiki/Advanced_Encryption_Standard"
        $url_tor = "www.torproject.org/download/download-easy.html"
    condition:
        1 of ($locky_*) or all of ($url_*)
}
