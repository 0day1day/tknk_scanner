import "pe"

rule win_badnews_w0 {
    meta:
        author = "Florian Roth"
        reference = "http://blog.fortinet.com/2017/04/05/in-depth-look-at-new-variant-of-monsoon-apt-backdoor-part-2"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "\\Microsoft\\Windows\\coco.exe" fullword ascii
        $x2 = ":\\System Volume Information\\config" fullword ascii
        $x3 = " cscript.[BACKSPA[PAGE DO[CAPS LO[PAGE UPTPX498.dTPX499.d" fullword wide

        $s1 = "\\Microsoft\\Templates\\msvcrt.dll" fullword ascii
        $s2 = "%04d/%02d/%02d %02d:%02d:%02d - {%s}" fullword wide
        $s3 = "wininet.dll    " fullword ascii
        $s4 = "DMCZ0001.dat" fullword ascii
        $s5 = "TZ0000001.dat" fullword ascii
        $s6 = "\\MUT.dat" fullword ascii
        $s7 = "ouemm/emm!!!!!!!!!!!!!" fullword ascii
    condition:
        ( 1 of ($x*) or 3 of them )
}
