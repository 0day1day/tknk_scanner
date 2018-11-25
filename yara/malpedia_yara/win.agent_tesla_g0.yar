rule win_agent_tesla_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180408"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_net1a = ".Resources"
        $str_net1b = /[0-9a-zA-Z]\x00\.\x00p\x00n\x00g/
        $str_net1c = /[0-9a-zA-Z]\x00\.\x00j\x00p\x00/
        $str_net11 = "ComVisibleAttribute" fullword
        $str_net13 = "ClearProjectError" fullword
        $str_net15 = "BlockCopy" fullword 
        $str_net16 = "GetBytes" fullword
        $str_net17 = "GetURLHashString" fullword
        $str_net20 = "8.0.0.0" fullword
        $str_net30 = "color:#000000;"
        $str_net40 = "CREATE TABLE \"logins\"" wide
        $str_net41 = "IELibrary\\IELibrary"

        $str_stealagent1 = "@1B2c3D4e5F6g7H8" wide ascii
        $str_stealagent2 = "aGQ1Afik6NampDT5sJEQE4Z0wpsMw0IDAD06rrSswXrKzJ5Cg0G=" wide ascii
        $str_stealagent3 = "amp4Z0wpKzJ5Cg0GDT5sJD0sMw0IDAsaGQ1Afik6NwXr6rrSEQE=" wide ascii
        $str_stealagentA = "taskmgr"
        $str_stealagentB = "regedit"
        $str_stealagentC = "webpanel" wide ascii
        $str_stealagentD = "appdata" wide ascii

        $str_steal1 = "GetWinSCPPasswords" fullword
        $str_steal2 = "FlashFXP" fullword
        $str_steal3 = "JDownloader" fullword
        $str_steal4 = "SmartFTP" fullword
        $str_steal9 = "Path=([A-z0-9\\/\\.]+)"
        $str_stealA = "WinSCP 2" fullword
        $str_stealB = "Aerofox\\Foxmail\\V3"
        $str_stealC = "FileZilla\\recentservers.xml" wide ascii nocase
        $str_stealD = "Paltalk" wide ascii nocase

    condition:
       (7  of ($str_net*) and 3 of ($str_steal*) )
       or (3 of ($str_stealagent*) and 5 of ($str_*))
}


