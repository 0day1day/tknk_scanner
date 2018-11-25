import "pe"

rule win_mosquito_w0 {
    meta:
        description = "Detects malware sample from Turla Mosquito report"
        author = "Florian Roth"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = ".?AVFileNameParseException@ExecuteFile@@" fullword ascii
        $s3 = "no_address" fullword wide
        $s6 = "SRRRQP" fullword ascii
        $s7 = "QWVPQQ" fullword ascii
    condition:
        pe.imphash() == "cd918073f209c5da7a16b6c125d73746" or all of them
}
