rule win_pony_g0 {
    meta:
        author = "Various authors / Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170418"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $gate = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"

    condition:
        any of them
}
