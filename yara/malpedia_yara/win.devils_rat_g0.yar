rule win_devils_rat_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        sample = "e23605d07236e205652459436cc69fcf676fbe27e5584e0022bd5b72602778c5"
        malpedia_version = "20170918"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        
        $pdb = "Devils-Rat 3.0"
        $string_0 = "taskmgrkiller.Type" wide

    condition:
       all of them
}
