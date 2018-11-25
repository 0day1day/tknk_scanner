rule win_kovter_g0 {
    meta:
       author = "mak"
       function="extract_cfg"
        malpedia_version = "20170412"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $cfg0 = "::lcpu" fullword wide
        $cfg1 = "lcpu::" fullword wide
        $cfg2 = ":DD1D" fullword wide
        $cfg3 = "DD1D:" fullword wide
        $cfg4 = ":DD2D" fullword wide
        $cfg5 = "DD2D:" fullword wide
        $cfg6 = ":DD3D" fullword wide
        $cfg7 = "DD3D:" fullword wide
        $cfg8 = ":DD4D" fullword wide
        $cfg9 = "DD4D:" fullword wide
        $cfg10 = ":DD5D" fullword wide
        $cfg11 = "DD5D:" fullword wide
        $cfg12 = ":DD6D" fullword wide
        $cfg13 = "DD6D:" fullword wide
        $cfg14 = ":DD7D" fullword wide
        $cfg15 = "DD7D:" fullword wide
        $cfg16 = ":DD8D" fullword wide
        $cfg17 = "DD8D:" fullword wide
        $cfg18 = ":DD9D" fullword wide
        $cfg19 = "DD9D:" fullword wide
        $cfg20 = ":DD10D" fullword wide
        $cfg21 = "DD10D:" fullword wide
        $cfg22 = ":DD11D" fullword wide
        $cfg23 = "DD11D:" fullword wide
        $cfg24 = ":DD12D" fullword wide
        $cfg25 = "DD12D:" fullword wide
        $cfg26 = ":DD13D" fullword wide
        $cfg27 = "DD13D:" fullword wide
        $cfg28 = ":DD14D" fullword wide
        $cfg29 = "DD14D:" fullword wide
        $cfg30 = ":DD15D" fullword wide
        $cfg31 = "DD15D:" fullword wide
        $cfg32 = ":DD16D" fullword wide
        $cfg33 = "DD16D:" fullword wide
        $cfg34 = ":DD17D" fullword wide
        $cfg35 = "DD17D:" fullword wide
        $cfg36 = "num:" fullword wide
        $cfg37 = "path<<" fullword wide
        $cfg38 = ">>path" fullword wide
        $rsc_name = "DATA" fullword wide
    condition:
        $rsc_name and 10 of ($cfg*)
}
