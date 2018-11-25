rule win_trickbot_g1 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        info = "dll loader"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        /* based on a single example, rule likely needs refinement against more unpacked loaders...
            loc_401011:
            30 08                         xor     [eax], cl
            69 C9 29 E5 0A 00             imul    ecx, 714025
            FF 4D 0C                      dec     [ebp+arg_4]
            81 C1 69 4D 02 00             add     ecx, 150889
            40                            inc     eax
            83 7D 0C 00                   cmp     [ebp+arg_4], 0
            77 E8                         ja      short loc_401011
        */ 
        $decrypt_loop = { 30 08 69 c9 ?? ?? ?? ?? ff 4d 0c 81 c1 ?? ?? ?? ?? 40 83 7d 0c 00 77 e8 } 
 
    condition:
    all of them
}
