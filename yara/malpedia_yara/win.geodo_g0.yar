rule win_geodo_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		date = "2014-12-10"
		sample = "unpacked: 0e65d3fc6fa073ba8ef8a24551467c3118e94d22"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings: 
        $cnc_url_1 = "http://%u.%u.%u.%u:%u/%x/%x" ascii
        $cnc_url_2 = "http://%s/%x/%x" ascii
        $mutex_1 = "%s_%s_%x%x" ascii
        $mutex_2 = "%s_%s_%X%X" ascii
        $registry_nesting_0 = "Software\\Netscape\\5.0\\%x\\r%x" wide ascii
        $registry_nesting_1 = "Software\\Netscape\\5.0\\%x\\q%x" wide ascii
        $ua = "Mozilla/4.0" wide ascii
        $rm_x_1 = "rm%x" wide
        // most newer versions store the C&C IP addresses as dword (in binary format)
        // this hex pattern exploits how Geodo prepares the IP address for the URL format string:
        // push 8080
        // <placeholder>
        // shr eax, 08
        // shr <reg>, 10
        // movzx < placeholder>
        $push_port_shift_ip = {68 90 1f 00 00 [1-6] C1 E8 (08 | 10) C1 E? (08 | 10) 0F}
        // that's for "old" versions around 2014-05
        $cnc_url_3 = "http://%s/%s" ascii
        $rm_x_2 = "%XRM" wide
        
    condition:
        (any of ($cnc_url_*)) and (any of ($mutex_*)) and (all of ($registry_*)) and $ua and (any of ($rm_x_*)) or ($cnc_url_3 and $rm_x_2 and $mutex_2) or $push_port_shift_ip
}
