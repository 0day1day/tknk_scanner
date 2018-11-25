rule win_grok_g0 {
    meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de"
        malpedia_version = "20170603"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $str_0 = "upamodebip"
        $path = "\\device\\harddiskdmvolumes\\physicaldmvolumes\\blockvolume" wide
        

    condition:
        all of them
}
