rule win_evilpony_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        contribution = "pnx, removed FPs vs normal Pony"
        malpedia_version = "20171113"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $post_data1 = "FILEHDRX"
        $post_data2 = "FILEPKDX"
        $post_data3 = "STATUS_OK"
        $post_data4 = "CReportPassword"
        // $post_data5 = "NCRYPTED" #fp
        
        $comm_url_decoder = { 8D ?? ?? 8A [1-4] 32 ?? 80 ?? ?? 42 }
        $comm_data_decoder1 = { F6 C1 01 74 ?? D1 E9 81 F1 [4] EB ?? D1 E9 4E }
        $comm_data_decoder2 = { 33 C8 81 E1 FF 00 00 00 C1 E8 08 33 [2-6] 42 }
        
        //$steal1 is only in CRE stealer, but not in Pony. Rest below is in Pony as well
        $steal1= "logins.json"
        
        $steal2= "signons.sqlite"
        $steal3= "prefs.js"
        $steal4= "signons.txt"
        $steal5= "signons2.txt"
        $steal6= "signons3.txt"
        $steal7= "profiles.ini"
        $steal8= "moz_logins"
        $steal9= "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2"
        $aplib1 = "aPLib"
        $aplib2 = "www.ibsensoftware.com"
        $guid = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
        
        $part_of_sha1 = { 23 d1 2b ca c1 e1 03 83 f8 04 }

    condition:
        $part_of_sha1 and ( (all of ($steal*)) and (all of ($aplib*)) and $guid ) or (all of ($post*)) or ( (1 of ($post*)) and 1 of ($comm*)) 
}

