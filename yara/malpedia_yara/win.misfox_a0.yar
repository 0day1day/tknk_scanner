rule win_misfox_a0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann@fkie.fraunhofer.de>"
		date = "2016-04-29"
        malpedia_version = "20170310"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"


    /*
        ####### combined PRNG from both 32bit + 64bit

        69 48 ?? FD 43 03 00          imul    ecx, [eax+14h], 343FDh
        81 C1 C3 9E 26 00             add     ecx, 269EC3h
        89 48 ??                      mov     [eax+14h], ecx
        C1 E9 10                      shr     ecx, 10h
        81 E1 FF 7F 00 00             and     ecx, 7FFFh
        8B C1                         mov     eax, ecx
        [0 or 4]
        C3                           retn

        ####### length == 8 + rand%4:
        48                            dec     eax
        83 C8 FC                      or      eax, 0FFFFFFFCh
        40                            inc     eax
        83 C0 08                      add     eax, 8
        
        or 64bit:
        FF C8                         dec     eax
        83 C8 FC                      or      eax, 0FFFFFFFCh
        FF C0                         inc     eax
        83 C0 08                      add     eax, 8
    */

    strings: 
	  $prng_0 = {FD 43 03 00 81 C1 C3 9E 26 00 89 48}
	  $prng_1 = {C1 E9 10 81 E1 FF 7F 00 00 }
	  $dga_len_32 = {48 83 C8 FC 40 83 C0 08}
	  $dga_len_64 = {FF C8 83 C8 FC FF C0 83 C0 08}
        
    condition:
	  (all of ($prng_*)) and (#dga_len_32 > 1 or #dga_len_64 > 1)
}
