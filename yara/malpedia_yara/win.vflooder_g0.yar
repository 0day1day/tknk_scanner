rule win_vflooder_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171223"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_vt      = "virustotal.com" wide ascii
        $str_vturl   = "/vtapi/v2/file/scan" wide ascii
        $str_httpA   = "boundary=------%015d" wide ascii
        $str_boundA1 = "--------%015d\x0D\x0A"
        $str_boundA2 = "--------%015d--\x00"
        $str_httpB   = "boundary=--------%u" wide ascii
        $str_boundB1 = "----------%u\x0D\x0A"
        $str_boundB2 = "----------%u--\x00"
        $str_VM      = "VMGrab"
        $str_sstart  = "%s\\*" wide
        $str_ijeg    = "image/jpeg" wide

    condition:
        5 of them
}
