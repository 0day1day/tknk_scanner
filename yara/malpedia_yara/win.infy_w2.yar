import "pe"

rule win_infy_w2 {
    meta:
        description = "Detects Foudre Backdoor"
        author = "Florian Roth"
        info = "foudre backdoor"
        reference = "https://goo.gl/Nbqbt6"
        date = "2017-08-01"
        hash1 = "7c6206eaf0c5c9c6c8d8586a626b49575942572c51458575e51cba72ba2096a4"
        hash2 = "db605d501d3a5ca2b0e3d8296d552fbbf048ee831be21efca407c45bf794b109"
        malpedia_version = "20170803"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        /* $s1 = "Project1.dll" fullword ascii */
        /* Better: Project1.dll\x00D1 */
        $s1 = { 50 72 6F 6A 65 63 74 31 2E 64 6C 6C 00 44 31 }
        $s2 = "winmgmts:\\\\localhost\\root\\SecurityCenter2" fullword wide
        $s3 = "C:\\Documents and Settings\\All Users\\" fullword wide
    condition:
        filesize < 2000KB and 3 of them or (2 of them and pe.exports("D1"))
}
