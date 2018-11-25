rule win_necurs_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180103"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $tmpfile_0 = "%s%08x-%04x-%04x-%04x-%04x%04x%04x.tmp" wide
        $tmpfile_1 = "%s%08x-%04x-%04x-%04x-%08x%04x.tmp" wide
        $mutex = "NitrGB" wide

    condition:
       1 of ($tmpfile_*) and $mutex
}
