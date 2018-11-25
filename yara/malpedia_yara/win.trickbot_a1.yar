rule win_trickbot_a1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        info = "banker component"
        malpedia_version = "20170608"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $s_1  = "dpost" fullword
        $s_2  = "dinj" fullword
        $s_2U = "|DINJ|"
        $s_3  = "sinj" fullword
        $s_3U = "|DINJ|"
        $s_4  = "\\\\.\\pipe\\pidplacesomepipe"
    condition:
        (4 of ($s_*))
}
