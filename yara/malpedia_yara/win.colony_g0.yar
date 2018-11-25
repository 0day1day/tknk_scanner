rule win_colony_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180417"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.colony"
    strings:
        $key   = "1Q2a3k79" ascii
        $comm1 = "&region="
        $comm2 = "&referrer="
        $comm3 = "&lang="
        $comm4 = "&browser="

    condition:
        3 of them
}
