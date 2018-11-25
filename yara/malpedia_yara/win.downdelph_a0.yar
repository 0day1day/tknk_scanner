rule win_downdelph_a0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180302"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"
	    
    strings: 
        $classname = "TMyDownloader"
        $url_params_0 = "&as_oq=" wide
        
    condition:
       all of them
}
