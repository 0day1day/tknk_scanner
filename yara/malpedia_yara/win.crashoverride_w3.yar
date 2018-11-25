rule win_crashoverride_w3 { 
    meta:
        description = "IEC-104 Interaction Module Program Strings"
        author = "Dragos Inc"
        reference = "https://dragos.com/blog/crashoverride/"
        malpedia_version = "20170615"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:      
        $s1 = "IEC-104 client: ip=%s; port=%s; ASDU=%u" nocase wide ascii 
        $s2 = " MSTR ->> SLV" nocase wide ascii 
        $s3 = " MSTR <<- SLV" nocase wide ascii 
        $s4 = "Unknown APDU format !!!" nocase wide ascii 
        $s5 = "iec104.log" nocase wide ascii 
    condition:      
        any of ($s*)
}
