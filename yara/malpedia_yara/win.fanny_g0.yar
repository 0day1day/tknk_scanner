rule win_fanny_g0 {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
        contribution = "pnx"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
        source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/Equation.yar"
        malpedia_version = "20170925"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $a1="prkMtx" wide
        $a2="cnFormSyncExFBC" wide
        $a3="cnFormVoidFBC" wide
        $a4="cnFormSyncExFBC"
        $a5="cnFormVoidFBC"
        $fanny = "fanny.bmp"
    condition:
        all of them
}
