rule win_zeroevil_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180920"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $zeroevil  = "Software\\ZeroEvil" wide ascii
        $logs_gate = "logs_gate.php"
        $c_plugin  = "plugin="
        $c_report  = "&report="

    condition:
        3 of them
}
