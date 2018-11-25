rule win_quant_loader_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170309"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $fw_0 = " advfirewall firewall add rule name=\""
        $fw_1 = "\" program=\""
        $fw_2 = "\" dir=Out action=allow"
        $fw_3 = "Quant"

        $c2_0 = { E8 [4] 80 3D [4] 00 74 ?? C7 04 24 [4] E8 ?? ?? FF FF }
        $c2_1 = { 00 04 00 00 C7 44 24 ?? 00 00 00 00 C7 04 24 [4]  E8 [4] C7 44 24 ?? 00 04 00 00 }

 condition:
  (3 of ($fw*)) or (any of ($c2*))
}
