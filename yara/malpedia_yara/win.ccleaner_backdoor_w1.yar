import "pe"

rule win_ccleaner_backdoor_w1 {
    meta:
        author = "Florian Roth"
        reference = "https://goo.gl/puVc9q"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "Copyright (c) 2007 - 2011 Symantec Corporation" fullword wide
        $s2 = "\\\\.\\SYMEFA" fullword wide
    condition:
        all of them and pe.number_of_signatures == 0
}
