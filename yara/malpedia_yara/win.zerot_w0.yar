rule win_zerot_w0 {
    meta:
        description = "Detects malware from the Proofpoint CN APT ZeroT incident"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s6 = "jGetgQ|0h9=" fullword ascii
    condition:
        ( 10 of ($s*) ) or ( all of them )
}
