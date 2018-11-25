rule win_dircrypt_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>, Thorsten Jenke <jenke<at>cs.uni-bonn.de>"
		description = "DirCrypt"
		sample = "unpacked:9d4f3d55e21c2e1408877b151a13dd1d"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
      $rsa_key = "RSA1"
	  $http_string = "http://"
	  $tld = ".com"
	  $cnc_proto_0 = "SetPayInfo" wide ascii
	  $cnc_proto_1 = "SetPersonalInfo" wide ascii
	  $prng_value_1 = { 1d f3 01 00 }
	  $prng_value_2 = { 1f 0b 00 00 }
	  $prng_value_2_2 = { 14 0b 00 00 }
	  $prng_value_3 = { a7 41 00 00 }
        
    condition:
	  $rsa_key and $http_string and $tld and (all of ($cnc_proto_*)) and (3 of ($prng_value_*))
}
