rule win_arkei_stealer_w0 {
    meta:
        Author = "Fumik0_"
        Description = "Arkei Stealer"
        Date = "2018/07/10"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.predator"
        malpedia_version = "20181023"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
 
    strings:
        $s1 = "Arkei" wide ascii
        $s2 = "/server/gate" wide ascii
        $s3 = "/server/grubConfig" wide ascii
        $s4 = "\\files\\" wide ascii
        $s5 = "SQLite" wide ascii
 
    condition:
        all of ($s*)   
}
