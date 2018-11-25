rule win_goodor_w0 {
    meta:
        author = "NCSC"
        hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
        malpedia_version = "20180413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $a1 = { 35 34 36 35 4B 4A 55 54 5E 49 55 5F 29 7B 68 36 35 67 34 36 64 66 35 68 }
        $a2 = { fb ff ff ff 00 00 }
    condition:
        all of them
}
