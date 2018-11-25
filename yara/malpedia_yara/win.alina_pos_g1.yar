rule win_alina_pos_g1 {
    meta:
        author = "Slavo Greminger, SWITCH-CER"
        malpedia_version = "20180201"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings: 
        $alina_ua   = /Alina v\d+\.?\d+/ nocase wide ascii
        $alina_v    = "Alina v" nocase wide ascii
        $alina_pipe = "\\\\.\\pipe\\alina" nocase wide ascii

        $spark_ua   = /Spark v\d+\.?\d+/ nocase wide ascii
        $spark_v    = "Spark v" nocase wide ascii
        $spark_pipe = "\\\\.\\pipe\\spark" nocase wide ascii
        $spark_deb  = "\\Spark.pdb"

        $eagle_ua     = /Eagle Special v\d+\.?\d+/ nocase wide ascii
        $eagle_v      = "Eagle Special v" nocase wide ascii
        $eagle_pipe   = "\\\\.\\pipe\\eagle" nocase wide ascii

        $katrina_ua   = /Katrina v\d+\.?\d+/ nocase wide ascii
        $katrina_v    = "Katrina v" nocase wide ascii
        $katrina_pipe = "\\\\.\\pipe\\katrina" nocase wide ascii

    condition:
        2 of them
}




