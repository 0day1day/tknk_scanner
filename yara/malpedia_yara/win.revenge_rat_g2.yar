rule win_revenge_rat_g2 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        kudos = "Florian Roth / https://github.com/Neo23x0/signature-base/blob/master/yara/apt_revenge_rat.yar"
        info = "targets the builder of Revenge RAT"
        malpedia_version = "20180122"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        // builder
        $str_id_RevRat     = "Revenge-RAT" wide
        $str_id_RevClient  = "Revenge-RAT Client" wide
        $str_id_Rev201x    = "Revenge-RAT 201" wide
        $str_id_napoleon   = "N A P O L E O N" wide
        $str_id_NK         = "*-]NK[-*" wide
        $str_id_Explosion  = "Nuclear Explosion" wide
        $str_id_Mutex      = "RV_MUTEX" wide

        $str_ServerID      = "- Server ID :" wide
        $str_IPAddr        = "IP Address :" wide
        $str_ComputerUserA = "User name / Computer name :" wide
        // also used in Eagle RAT an Small-Net RAT
        $str_ComputerUserB = "Computer / User" wide
        $str_PhysicalMem   = "Physical Memory :" wide
        $str_Processors    = "select * from Win32_Processor" wide

    condition:
        (1 of ($str_id_*) and 2 of ($str_*))
        or 3 of ($str_*)
}
