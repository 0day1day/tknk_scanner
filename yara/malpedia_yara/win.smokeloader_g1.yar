rule win_smokeloader_g1 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		sample = "unpacked: 7bd631b8c5a03eb5676c6dff243d632a"
        malpedia_version = "20170529"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $initial_prologue = { 0f 31 0b 05 ?? ?? ?? ?? c1 d0 02 05 78 56 34 12 19 d0 }
        
    condition:
        all of them
} 
