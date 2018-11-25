rule win_tinba_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		sample = "1977f1f2ec9cf5af31926b16e683d39f"
        malpedia_version = "20170605"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        /* 
        contains usable unencrypted strings, however, they are used in a special way that allows precise pinpointing:
        Tinba uses "call-over-string" to save space and in order to push string pointers to the stack (mixed code/data)
        This looks the following:
          call XXXX
          db '\iexplore.exe', 0
          [...] more code, using the pushed string pointer [...]
        */   
        $call_over_iexplore = {E8 0D 00 00 00 5C 69 65 78 70 6C 6F 72 65 2E 65 78 65 }
        $call_over_opera = { E8 0A 00 00 00 5C 6F 70 65 72 61 2E 65 78 65 }
        $call_over_chrome_main = { E8 0B 00 00 00 43 68 72 6F 6D 65 4D 61 69  6E }
        
        $call_over_cfgdat = {E8 0A 00 00 00 5C 63 66 67 2E 64 61 74 }
        $call_over_webdat = {E8 0A 00 00 00 5C 77 65 62 2E 64 61 74 }
        $call_over_binexe = {E8 0A 00 00 00 5C 62 69 6E 2E 65 78 65 }
        $call_over_explorer = {E8 0E 00 00 00 5C 65 78 70 6C 6F 72 65 72 2E 65 78 65 00 }
        $call_over_firefox = {E8 0C 00 00 00 66 69 72 65 66 6F 78 2E 65 78 65 00 }
        $call_over_chrome = {E8 0B 00 00 00 63 68 72 6F 6D 65 2E 65 78 65 00 }
        $call_over_signs = {E8 0C 00 00 00 73 69 67 6E 73 5F 66 6F 75 6E 64 00 }
        $call_over_in_chrome_retn = {E8 0F 00 00 00 69 6E 5F 63 68 72 6F 6D 65 5F 72 65 74 6E 00 }
        
        $call_data_before = {E8 (0C|0D|0E) 00 00 00 0A 64 61 74 61 5F 62 65 66 6f 72 65 }
        $call_data_inject = {E8 (0C|0D|0E) 00 00 00 0A 64 61 74 61 5F 69 6e 6a 65 63 74 }
        $call_data_after = {E8 (0B|0C|0D) 00 00 00 0A 64 61 74 61 5F 61 66 74 65 72 }
        $call_data_end = {E8 (09|0A|0B) 00 00 00 0A 64 61 74 61 5F 65 6e 64 }

        // "%BOTUID%"
        $call_bot_uid = {E8 (08|09) 00 00 00 25 42 4F 54 55 49 44 25 }
        
        
    condition:
       (3 of ($call_over_*)) and (all of ($call_data_*)) and $call_bot_uid
}

