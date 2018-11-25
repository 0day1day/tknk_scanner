rule win_dyre_g1 {
	meta:
	   author = "mak"
	   module = "dyre"
	   function = "dll_get_config"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

	strings:
	   $req1 = "/%s/%s/0/%s/%d/%s/" fullword ascii
	   $req2 = "/%s/%s/%d/%s/" fullword ascii
	   $req3 = "/%s/%s/%d/%s/%s/" fullword ascii
	   $req4 = "/%s/%s/5/%s/%s/" fullword ascii
	   
	condition:
	   all of them
}
