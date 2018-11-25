rule win_njrat_g1 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        contributions = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180108"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_a_TAP       = "[TAP]" wide
        $str_a_Enter     = "[ENTER]" wide

        $str_v_072 = "[endof]" wide
        $str_v_073 = "GiveMeAdmin" wide
        $str_v_07d  = "netsh firewall delete allowedprogram " wide


    condition:
        all of ($str_a_*) and any of ($str_v_*)
}
