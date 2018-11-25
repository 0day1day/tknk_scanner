rule win_bka_trojaner_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180525"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bka_trojaner"
    strings:
        $str_petrol      = "PETROLSTATIONS" wide
        $str_bka         = "Mitteilung des Bundeskriminalamtes" wide ascii
        $str_bwin3       = "\\bwin3\\"
        $str_verflichtet = "verflichtet" wide ascii

    condition:
       3 of them
}
