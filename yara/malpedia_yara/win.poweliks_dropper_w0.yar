rule win_poweliks_dropper_w0 {
    meta:
        author = "Adam Burt (adam_burt@symantec.com)"
        md5hash = "181dbed16bce32a7cfc15ecdd6e31918"
        sha1hash = "b00a9e4e12f799a1918358d175f571439fc4b45c"
	    source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/poweliks_dropper.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $s1 = "NameOfMutexObject"
        $c1 = {2F 2E 6D 2C}
        $c2 = {76 AB 0B A7}

    condition:
        $c1 at 0x104a0 or ($s1 and $c2 at 0x104a8)

}
