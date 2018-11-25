rule win_cryptowall_g1 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20170603"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $cryptolocker_clone = "G:\\crown\\Release\\crown.pdb"
        
        $cryptodefense_0 = "%USER_CODE%"
        $cryptodefense_1 = "%TOR_SERVICE_URL%"
        
        $cryptowall_all = { C1 E9 08 8B 55 F4 0F BE 02 33 45 F8 25 FF 00 00 00 33 0C 85 }
        
        
    condition:
        $cryptolocker_clone or all of ($cryptodefense_*) or all of ($cryptowall_*)
        
}
