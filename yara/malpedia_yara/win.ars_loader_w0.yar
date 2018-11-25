rule win_ars_loader_w0 { 
    meta:
        author = "Flashpoint Intel"
        reference = "https://www.flashpoint-intel.com/wp-content/uploads/2018/04/ARS-VBS-Loader-Yara-Rule.pdf"
        malpedia_version = "20180529"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings: 
        $a1 = "Array(" 
        $a2 = "crypted&" 
        $a3 = "execute(crypted)" 
        $b1 = "ToDecrypt" 
        $b2 = "replace(ToDecrypt," 
        $b3 = "execute(ToDecrypt)" 
        $c1 = "Randomize" 
        $c2 = "execute(" 
        $c3 = "Wscript.Sleep(" 
        $d1 = "changeCNC()" 
        $d2 = "downloadexecutep" 
        $d3 = "sGetAV" 
        $d4 = "AgonyMutex" 
        $d5 = "dos(hst, cnt)" 
    condition:  
        ((all of ($a*)) or 
        (all of ($b*)) or 
        (all of ($c*)) or 
        (all of ($d*))) 
}
