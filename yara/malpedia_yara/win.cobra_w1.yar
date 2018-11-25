import "pe"

rule win_cobra_w1 {
    meta:
        source = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/#_footnote_2"
        malpedia_version = "20170512"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    condition:
        (pe.version_info["InternalName"] contains "SERVICE.EXE" or
        pe.version_info["InternalName"] contains "MSIMGHLP.DLL" or
        pe.version_info["InternalName"] contains "MSXIML.DLL")
        and pe.version_info["CompanyName"] contains "Microsoft Corporation"
}
