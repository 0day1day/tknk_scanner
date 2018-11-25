rule win_contopee_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		sample = "766d7d591b9ec1204518723a1e5940fd6ac777f606ed64e731fd91b0b4c3d9fc"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $ciphersuites = { 03 00 04 00 05 00 06 00 08 00 09 00 0a 00 0d 00 10 00 11 00 12 00 13 00 14 00 15 00 16 00 2f 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 3c 00 3d 00 3e 00 3f 00 40 00 41 00 44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00 68 00 69 00 6a 00 6b 00 84 00 87 00 88 00 96 00 ff 00 01 c0 02 c0 03 c0 04 c0 05 c0 06 c0 07 c0 08 c0 09 c0 0a c0 0b c0 0c c0 0d c0 0e c0 0f c0 10 c0 11 c0 12 c0 13 c0 14 c0 23 c0 24 c0 27 c0 2b c0 2c c0 ff fe }
        
        // 766d7d591b9ec1204518723a1e5940fd6ac777f606ed64e731fd91b0b4c3d9fc
        $plain_strings_0 = "canconnect- true."
        $plain_strings_1 = "load_cfg - ret=%d"
        $plain_strings_2 = "before wakeup."
        
        // c05329f101979fa75ca297c4f77c8cd69fe8eb499d4f693550b734beb9f564b9
        $plain_strings_3 = "netsh firewall delete portopening TCP"
        $plain_strings_4 = "netsh firewall add portopening TCP %d"
        $plain_strings_5 = "Windows Firewall Remote Management"

    condition:
       $ciphersuites and (3 of ($plain_strings_*))
}
