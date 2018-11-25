rule win_kronos_g1 {

    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        date = "2017-08-04"
        malpedia_version = "20170804"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $b0 = { 6a 40 68 00 30 00 00 68 00 20 00 00 33 db }
        $b1 = { 56 57 8d 85 54 fe ff ff 50 68 02 02 00 00 }

    condition:
        all of them
}
