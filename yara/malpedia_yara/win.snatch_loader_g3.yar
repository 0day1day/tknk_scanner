rule win_snatch_loader_g3 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        info = "targets snatch loader's detects module"
        malpedia_version = "20180103"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $component_name = "detects_component.dll"
        // sub eax, *
        // stosd
        // xor eax, *
        // stosd
        // add eax, *
        // stosd
        // xor ...
        $dword_obfuscation = {2D [4] AB 35 [4] AB 05 [4] AB 35}

    condition:
       all of them
}
