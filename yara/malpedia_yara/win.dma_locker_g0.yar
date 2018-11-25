rule win_dma_locker_g0 { 
    meta:
        author = "mak"
        function = "madlocker"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $debug_s0="[+] Plik jest aktualnie zaszyfrowany, pomijanie.." fullword
        $debug_s1="[*] Rozmiar pliku = %I64d bajtow.." fullword
        $debug_s2="[+] Rozpoczeto szyfrowanie pliku: %s" fullword
        $debug_s3="[+] Zakonczono szyfrowanie pliku: %s" fullword
        $debug_s4="[+] Rozpoczeto zapisywanie z pamieci do pliku: %s" fullword
        $debug_s5="[+] Zakonczono zapisywanie z pamieci do pliku: %s" fullword
        $debug_s6="[*] Plik jest aktualnie odszyfrowany, pomijanie.." fullword
        $debug_s7="[+] Rozpoczeto deszyfrowanie pliku: %s" fullword fullword
        $debug_s8="[+] Zakonczono deszyfrowanie pliku: %s" fullword fullword

        $s0 = "Wszystkie twoje pliki zostaly zaszyfrowane przez DMA-Locker!" fullword
        $s1 = "DMA Locker" fullword

        $debug_s0_en="[+] Starting decrypting file: %s" fullword
        $debug_s1_en="[+] Decrypting file finished: %s" fullword
        $debug_s2_en="[+] Starting saving file from memory: %s" fullword

    condition:
        3 of ($debug_s*) or any of ($s*)
}
