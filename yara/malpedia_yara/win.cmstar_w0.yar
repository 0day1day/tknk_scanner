import "pe"

rule win_cmstar_w0 {
    meta:
        description = "Detects CMStar Malware"
        author = "Florian Roth"
        reference = "https://goo.gl/pTffPA"
        date = "2017-10-03"
        hash1 = "16697c95db5add6c1c23b2591b9d8eec5ed96074d057b9411f0b57a54af298d5"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "UpdateService.tmp" fullword ascii
        $s2 = "StateNum:%d,FileSize:%d" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and (pe.imphash() == "22021985de78a48ea8fb82a2ff9eb693" or pe.exports("WinCred") or all of them)
}
