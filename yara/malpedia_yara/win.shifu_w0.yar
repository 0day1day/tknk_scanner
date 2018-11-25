rule win_shifu_w0 {
	meta:
		description = "Detects SHIFU Banking Trojan"
		author = "Florian Roth"
		contribution = "Daniel Plohmann"
		reference = "http://goo.gl/52n8WE"
		date = "2015-10-31"
		score = 70
		hash1 = "0066d1c8053ff8b0c07418c7f8d20e5cd64007bb850944269f611febd0c1afe0"
		hash2 = "3956d32a870d81be34cafc867769b2a2f55a96360070f1cb3d9addc2918357d5"
		hash3 = "3fde1b2b50fcb36a695f1e6bc577cd930c2343066d98982cf982393e55bfce0d"
		hash4 = "457ad4a4d4e675fe09f63873ca3364434dc872dde7d9b64ce7db919eaff47485"
		hash5 = "51edba913e8b83d1388b1be975957e439015289d51d3d5774d501551f220df6f"
		hash6 = "6611a2b79a3acf0003b1197aa5bfe488a33db69b663c79c6c5b023e86818d38b"
		hash7 = "72e239924faebf8209f8e3d093f264f778a55efb56b619f26cea73b1c4feb7a4"
		hash8 = "7a29cb641b9ac33d1bb405d364bc6e9c7ce3e218a8ff295b75ca0922cf418290"
		hash9 = "92fe4f9a87c796e993820d1bda8040aced36e316de67c9c0c5fc71aadc41e0f8"
		hash10 = "93ecb6bd7c76e1b66f8c176418e73e274e2c705986d4ac9ede9d25db4091ab05"
		hash11 = "a0b7fac69a4eb32953c16597da753b15060f6eba452d150109ff8aabc2c56123"
		hash12 = "a8b6e798116ce0b268e2c9afac61536b8722e86b958bd2ee95c6ecdec86130c9"
		hash13 = "d6244c1177b679b3d67f6cec34fe0ae87fba21998d4f5024d8eeaf15ca242503"
		hash14 = "dcc9c38e695ffd121e793c91ca611a4025a116321443297f710a47ce06afb36d"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/shifu_trojan.yar"
        malpedia_version = "20170603"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
		$x1 = "\\Gather\\Dividerail.pdb" ascii

		$s0 = "\\payload\\payload.x86.pdb" ascii
		$s1 = "USER_PRIV_GUEST" fullword wide
		$s2 = "USER_PRIV_ADMIN" fullword wide
		$s3 = "USER_PRIV_USER" fullword wide
		$s4 = "%ws\\%ws" wide
	condition:
		($x1 or 5 of ($s*))
}
