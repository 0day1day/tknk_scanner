rule win_corebot_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170531"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $core_cert = "core.cert"
        $core_dga = "core.dga"
        $core_gh = "core.gh"
        $core_guid = "core.guid"
        $core_inject = "core.inject"
        $core_install = "core.install"
        $core_no = "core.no"
        $core_plugins = "core.plugins"
        $core_safe = "core.safe"
        $core_server = "core.server"
        $core_vm = "core.vm"
        $ops_scrambler1 = {          31 [3] C1 C? 02 43 83 F? 40 72 F? }
        $ops_scrambler2 = { 83 C? 04 31 C?  C1 C? 1E    83 F? 20 72 F? }

    condition:
        (5 of ($core_*)) or (any of ($ops_*))
}
