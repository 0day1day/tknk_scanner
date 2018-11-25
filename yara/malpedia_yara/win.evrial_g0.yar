rule win_evrial_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180326"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.evrial"
    strings:
        $project_evrial = "Project Evrial" wide ascii
        $evrial_stealer = "Evrial.Stealer" wide ascii
        $qutra = "Qutra" wide ascii fullword
        $SiteUrl = "SiteUrl : {0}" wide ascii
        $Program = "Program : {3}" wide ascii

    condition:
        2 of them
}
