rule win_bunitu_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        reference = "https://blog.malwarebytes.com/threat-analysis/2015/07/revisiting-the-bunitu-trojan/"
        malpedia_version = "20171005"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $op_gethostbyname  = { E8 [4]  A3 [4]  C7 05 [4] 01 00 00 00   A3 [4]  C6 05 [4] 00   68  } 
        $op_xor_calcip     = { (2B C0|35 [4]  A3 [3] ??)  C7 05 [8]  66 C7 05 [4] 02 00  66 C7 05 [4] 02 00  2B C0 } 
        $op_zero           = { 3C 02  75 12  8A 06  F7 D2  46  EB 0B  2C 30  8D 0C 89  8D 0C 48  8A 06  46 }

    condition:
        2 of them
}

