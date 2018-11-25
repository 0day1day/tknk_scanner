rule win_cryptowall_g0 {
    meta:
	    author="mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
	    $help0 = "HELP_YOUR_FILES.TXT" wide fullword
	    $help1 = "HELP_YOUR_FILES.HTML" wide fullword
	    $help2 = "HELP_YOUR_FILES.PNG" wide fullword
	    $decrypt_ransom_note = { 55 8B EC 83 EC 0C 68 [4] 68 [4] 68 [4] 68 [4] 6A 02 E8 [4] 83 C4 14 85 C0}
	    $decrypt_url_list = {55 8B EC 83 EC 18 C7 45 F4 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 8D ?? F0 5? 8D ?? FC 5? 68 [4] 68 [4] 6A 02 E8 [4] 83 C4 14 85 C0}
	    $base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
	    $get_campaing_id = { 83 C4 04 8B ?? [4] 89 ?? 08 8B ?? [4] 83 C? 04 5? A1 [4] 50 68 [4] E8 [4] 83 C4 0C 85 C0 }
	    
    condition:
	    (any of ($help*) or  #base64 == 11) and $decrypt_ransom_note and $decrypt_url_list or $get_campaing_id
}
