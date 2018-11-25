rule win_kovter_a0 {
    meta: 
        author = "pnx"
        info = "created with malpedia YARA rule editor"
        malpedia_version = "20171014"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"
        
    strings:
        // Unicode strings found across versions in Kovter
        $string = "::lcpu" wide
        $string1 = "lcpu::" wide
        $string2 = ">>path" wide
        $string3 = "path<<" wide
        $string4 = "SOFTWARE\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BROWSER_EMULATION" wide

    condition:
        all of them
}
