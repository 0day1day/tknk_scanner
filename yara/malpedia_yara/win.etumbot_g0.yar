rule win_etumbot_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180111"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        // this already finds a bunch of etumbots
        $string_process = "Process Do not exit in 10 second, so i Kill it!"
        
        /*
          # some of them also have a very unique Sleep/GTC random loop, e.g. ESI/EDI may be swapped
          68 D0 07 00 00                push    7D0h
          FF 15 1C E0 40 00             call    ds:Sleep
          FF D7                         call    edi ; GetTickCount
          2B C3                         sub     eax, ebx
          3B C6                         cmp     eax, esi
          72 ED                         jb      short loc_403E20
        */
        $sleep_gtc = { 68 [2] 00 00 FF 15 [4] FF (D6|D7) 2B C3 3B (C6|C7) 72 }

    condition:
       any of them
}
