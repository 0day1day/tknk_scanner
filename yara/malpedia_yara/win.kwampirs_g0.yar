rule win_kwampirs_g0  {
   meta:
        description = "Yara rule for Kwampirs dropper"
        author = "CCIRC"
		md5 = "fac94bc2dcfbef7c3b248927cb5abf6d"
        date = "2018-04-24"
		ref = "https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia"
        malpedia_version = "20180425"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
   strings:
	// datablock overlap starting at offset 0x00423434
	$opcode1 = { 6C 35 E3 31 1B 23 F9 C9 65 EB F3 07 93 33 F2 A3 30 35 90 31 62 23 8A C9 11 EB 96 07 FE 33 C1 A3 5E 35 BF 31 30 35 90 31 62 23 8A C9 12 EB 9C 07 E4 33 C4 A3 58 35 BF 31 }
   condition:
      	all of them
}
