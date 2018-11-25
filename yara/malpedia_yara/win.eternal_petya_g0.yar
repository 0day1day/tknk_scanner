rule win_eternal_petya_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        info = "dropper"
        malpedia_version = "20180125"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $str_0 = "%ws C:\\Windows\\%ws,#1 %ws" wide

    condition:
       any of them
}
