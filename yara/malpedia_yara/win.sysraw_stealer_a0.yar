rule win_sysraw_stealer_a0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180927"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        //$str_vbp1      = "C:\\Work\\clipsa\\clipsa_new\\sources\\PClipsa.vbp" wide ascii
        //$str_vbp2      = "C:\\Work\\clipsa\\clipsa_rus\\sources\\PClipsa.vbp" wide ascii
        //$str_vbp3      = "C:\\Work\\felix\\sources\PFelix.vbp" wide ascii
        $str_clipsa     = "clipsa_" wide ascii
        $str_pclipsa    = "PClipsa" wide ascii
        $str_mclipsa    = "MClipsa" wide ascii
        $str_miclipsa   = "MIClipsa" wide ascii
        $str_pfelix     = "PFelix" wide ascii
        $str_MUBase     = "MUBase" wide ascii
        $str_MUReqs     = "MUReqs" wide ascii
        $str_MUCrypt    = "MUCrypt" wide ascii
        $str_MIWallet   = "MIWallet" wide ascii

        $str_CLIPS      = "--CLIPS" wide ascii
        $str_BRUTE      = "--BRUTE" wide ascii
        $str_PARSE      = "--PARSE" wide ascii
        $str_WALLS      = "--WALLS" wide ascii

        $str_WPCoreLog  = "WPCoreLog" wide ascii
        $str_AfterCI    = "After check instance" wide ascii 
        $str_Install    = "Install switch" wide ascii 
        $str_AfterTK    = "After taskkill" wide ascii 
        $str_AfterCF    = "After create FSO" wide ascii 
        $str_AfterFC    = "After filecopy" wide ascii 

        // WPSecurity/load.php
        $str_WPSecurity = "WPSecurity" wide ascii
          
    condition:
        3 of them
}
