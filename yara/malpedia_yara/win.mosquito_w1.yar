rule win_mosquito_w1 {
    meta:
        description = "Detects malware sample from Turla Mosquito report"
        author = "Florian Roth"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $a1 = "/scripts/m/query.php?id=" fullword wide
        $a2 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
        $a3 = "GetUserNameW fails" fullword wide

        $s1 = "QVSWQQ" fullword ascii
        $s2 = "SRRRQP" fullword ascii
        $s3 = "QSVVQQ" fullword ascii
    condition:
        2 of ($a*) or 4 of them
}
