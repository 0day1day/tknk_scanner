rule win_isr_stealer_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        comment = "ISR stealer is written in VB; part of this rule detects Nirsoft modules"
        malpedia_version = "20170625"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $UserAgent = "HardCore Software For : Public" wide

        $mem_url_1 = "&app"
        $mem_url_2 = "&pcname"
        $mem_url_3 = "&sitename"

    condition:
        $UserAgent or all of ($mem_*)
}
