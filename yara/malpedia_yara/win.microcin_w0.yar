import "pe"

rule win_microcin_w0 {
    meta:
        description = "Malware sample mentioned in Microcin technical report by Kaspersky"
        author = "Florian Roth"
        reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
        date = "2017-09-26"
        hash1 = "49816eefcd341d7a9c1715e1f89143862d4775ba4f9730397a1e8529f5f5e200"
        hash2 = "a73f8f76a30ad5ab03dd503cc63de3a150e6ab75440c1060d75addceb4270f46"
        hash3 = "9dd9bb13c2698159eb78a0ecb4e8692fd96ca4ecb50eef194fa7479cb65efb7c"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "e Class Descriptor at (" fullword ascii
        $s2 = ".?AVCAntiAntiAppleFrameRealClass@@" fullword ascii
        $s3 = ".?AVCAntiAntiAppleFrameBaseClass@@" fullword ascii
        $s4 = ".?AVCAppleBinRealClass@@" fullword ascii
        $s5 = ".?AVCAppleBinBaseClass@@" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and (4 of them or pe.imphash() == "897077ca318eaf629cfe74569f10e023")
}
