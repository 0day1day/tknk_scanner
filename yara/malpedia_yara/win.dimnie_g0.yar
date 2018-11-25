rule win_dimnie_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170814"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_tool = "toolbarqueries.google.com"
        $str_REQ1 = "?sourceid=navclient-ff"
        $str_REQ2 = "&features=Rank&client="
        $str_REQ3 = "navclient-auto-ff&ch="
        $str_UA1  = "Presto/2.12.388 Version/12.15"
        $str_UA2  = "AlexaToolbar/pUePRsFf-2.2"

    condition:
        4 of them
}
