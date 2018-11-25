import "pe"

rule win_runningrat_w0 {
	meta:
		author = "Florian Roth"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "C:\\USERS\\WIN7_x64\\result.log" fullword wide
        $x2 = "rundll32.exe %s RunningRat" fullword ascii
        $x3 = "SystemRat.dll" fullword ascii
        $x4 = "rundll32.exe %s ExportFunction" fullword ascii
        $x5 = "rundll32.exe \"%s\" RunningRat" fullword ascii
        $x6 = "ixeorat.bin" fullword ascii
        $x7 = "C:\\USERS\\Public\\result.log" fullword ascii

        $a1 = "emanybtsohteg" fullword ascii /* reversed goodware string 'gethostbyname' */
        $a2 = "tekcosesolc" fullword ascii /* reversed goodware string 'closesocket' */
        $a3 = "emankcosteg" fullword ascii /* reversed goodware string 'getsockname' */
        $a4 = "emantsohteg" fullword ascii /* reversed goodware string 'gethostname' */
        $a5 = "tpokcostes" fullword ascii /* reversed goodware string 'setsockopt' */
        $a6 = "putratSASW" fullword ascii /* reversed goodware string 'WSAStartup' */

        $s1 = "ParentDll.dll" fullword ascii
        $s2 = "MR - Already Existed" fullword ascii
        $s3 = "MR First Started, Registed OK!" fullword ascii
        $s4 = "RM-M : LoadResource OK!" fullword ascii
        $s5 = "D:\\result.log" fullword ascii
    condition:
        pe.imphash() == "c78ccc8f02286648c4373d3bf03efc43" or
        pe.exports("RunningRat") or
        1 of ($x*) or
        5 of ($a*) or
        3 of ($s*)
}
