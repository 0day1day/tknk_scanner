rule win_loda_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171009"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $autoit    = "autoit" fullword nocase
        $autoit_w  = "autoit" fullword nocase wide

        $str_ipscore   = "ip-score"
        $str_ipscore_w = "ip-score" wide
        $str_checkip   = "checkip"
        $str_checkip_w = "checkip" wide

    condition:
        any of ($autoit*) and 2 of ($str_*)
}
