rule win_orcus_rat_a0 {
    meta:
        author = "CCIRC"
        description = "Unpacked or In-Memory Orcus RAT Rule"
        reference = "https://blog.fortinet.com/2017/12/07/a-peculiar-case-of-orcus-rat-targeting-bitcoin-investors"
        contributions = "pnX / Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180523"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $a = "Orcus.Commands.Passwords."
        $c = "Orcus.Shared.Commands."
        $d = "Orcus.Plugins."
        $e = ".orcus.shared.dll."
        $f = "Orcus.CommandManagement"
        $b = "Orcus.Watchdog."
        $g = "Orcus.Core"
        $h = "PrepareOrcusFileToRemove"
        $s_orcus_application = "OrcusApplicationContext"
        $s_orcus_service = "Orcus_Service" ascii wide
        $s_orcus_code = "Orcus.CodeExecution" ascii wide
        $s_orcus_utilities = "Orcus.Utilities" ascii wide

    condition:
        6 of them
}
