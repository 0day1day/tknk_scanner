rule win_dridex_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        date = "2015-08-13"
        description = "Unpacked Dridex binary in memory"
        sample = "14e9840bdf98de7b9ad8aa0e9fc395ed7aefd31d75e92f7b5ab34a1d195a1328"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        // all expressive strings are encrypted, so we can target the string decryption method

        /***** loop for function decryption
           xor reg, [reg]
           ??
           xor ref, [reg+4]
        */
        $decrypt_string = { 33 ?? [0-2] 33 ?? 04 }

        /*****  XOR crypt loop
           add *
           add *
           add *
           mov reg, [reg+reg]
           xor [reg], reg
           (mov)
           inc reg
        */
        $crypt_loop = { 03 [1-2] 03 [1-2] 03 [1-2] 8A ?? ?? 30 ?? [0-3] 4?}
        
        $deref_this_0 = { 8B 41 0C 03 01 03 (44 | 45) [2-3] C2 04 00 }
        $deref_this_1 = { 8B 01 03 41 0C 03 (44 | 45) [2-3] C2 04 00 }

    condition:
       (any of ($deref_this_*)) and ($decrypt_string or #crypt_loop > 1)
}
