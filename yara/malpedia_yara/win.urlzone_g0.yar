rule win_urlzone_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de"
		description = "2013-07-10 URLZone Banking Trojan"
        malpedia_version = "20170511"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $mutex_a = "6A57BEED"         // crypted_1 - Mutex, static for 3 years now
        $itinj = "ITINJ"            // noncrypted - constant used for injects
        $itinit = "ITINIT"          // noncrypted - constant used for injects
        $itreq = "ITREQ"            // noncrypted - constant used for injects
        $itcmp = "ITCMP"            // noncrypted - constant used for injects
        $statusok = "ITOK"          // crypted_2 - constant used in C&C communication when reporting on injects
        $statuserr = "ITERR"        // crypted_2 - constant used in C&C communication when reporting on injects
        $injectfile = "INJECTFILE"  // crypted_2 - constant used in C&C communication when receiving injects
        $ithost = "ITHOST"          // crypted_2 - constant used in inject parsing
        
        $checkin_0 = "ipcnf="
        $checkin_1 = "sckport="
        $checkin_2 = "gate_urlzone"
        
        $dga_0 = "qwertyuiopasdfghjklzxcvbnm123945678"
        $dga_1 = ".net"
        $dga_2 = ".com"
        
    condition:
        ($mutex_a) or (4 of ($itinj,$itinit,$itreq,$itcmp)) or (4 of ($statusok,$statuserr,$injectfile,$ithost)) or (all of ($checkin_*)) or (all of ($dga_*))
}
