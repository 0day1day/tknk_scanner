rule win_trickbot_g4 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        info = "coverage for a range of missed loaders"
        malpedia_version = "20180125"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        // mov eax, [eax] 
        // cmp dword ptr [ecx+0Ch], 320033h
        $bin_loader401000 = { 8b 00 81 79 ?? 33 00 32 00 }

    condition:
       any of them
}
