rule win_synflooder_g0 {

    meta: 
        author = "pnx"
        info = "created with malpedia YARA rule editor"
        malpedia_version = "20171001"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $string = "your target's IP is : %s"
        $string2 = "your IP Addres is : %s"

    condition:
        all of them
}
