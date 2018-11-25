rule win_equationgroup_w0 {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
        source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/Equation.yar"
        note = "pnx: using this as a catchall for now, excluding fanny, which is covered by its own rule"
        malpedia_version = "20170925"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $a1="prkMtx" wide
        $a2="cnFormSyncExFBC" wide
        $a3="cnFormVoidFBC" wide
        $a4="cnFormSyncExFBC"
        $a5="cnFormVoidFBC"
        $fanny = "fanny.bmp"
    condition:
        any of ($a*) and not $fanny
}
