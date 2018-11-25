rule win_cerber_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de"
        malpedia_version = "20170603"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $cerber = "cerber"
        $v1_1  = "Keysize: %d, Encryption time: %d" wide
        $v1_2  = "Total files found: %d, Files crypted: %d" wide
        
        $v2_0 = "{PARTNER_ID}"
        $v2_1 = "{MD5_KEY}"
        
        $murmurhash_0 = { 51 2d 9e cc }
        $murmurhash_1 = { 93 35 87 1b }
        $murmurhash_2 = { 64 6b 54 e6 }
        
        $shared_code = { 8b f9 33 db 89 5d d8 89 5d fc 57 ff 15 }
        
    condition:
        ($cerber and (all of ($v1_*) or (all of ($v2_*)))) or ($shared_code and all of ($murmurhash_*))
        
}
