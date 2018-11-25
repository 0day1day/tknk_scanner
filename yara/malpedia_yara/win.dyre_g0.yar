rule win_dyre_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de"
        date = "2014-07-17"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        // Session Traversal used to determine the public IP of the compromised system, selected URLs
        $stun_0 = "stun.l.google.com" wide ascii
        $stun_1 = "stun.stunprotocol.org" wide ascii
        $stun_2 = "stun.iptel.org" wide ascii
        $botid = "botid"
        $mutex_0 = "Diper89" wide ascii
        $mutex_1 = "Diper89Pipe" wide ascii
        $mutex_2 = "RangisMutex5" wide ascii
        $mutex_3 = "RangisPipe6" wide ascii
        $md5_format_str = "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"  wide ascii

    condition:
        $botid and $md5_format_str and ((2 of ($mutex_*)) or (2 of ($stun_*)))
}
