rule win_galaxyloader_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180326"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.galaxyloader"
    strings:
        $str_pdb        = "GalaxyLoader.pdb"
        $str_galaxy     = "GalaxyLoad" wide
        $str_file       = "file:///" wide
        $str_fakeloader = "FakeLoad" wide ascii
        $str_lastreboot = "lastReboot" wide ascii

    condition:
        3 of them
}
