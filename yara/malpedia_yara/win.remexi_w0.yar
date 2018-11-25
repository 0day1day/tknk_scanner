rule win_remexi_w0 {
    meta:
        source = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
        malpedia_version = "20170410"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $c1   = { 00 3C 65 78 69 74 3E 00 }    /* <exit>  */
        $c2   = { 00 3C 69 64 3E 00 }          /* <id>    */
        $c3   = { 00 3C 72 65 6D 3E 00 }       /* <rem>   */
        $c4   = { 00 3C 63 6C 6F 73 65 3E 00}  /* <close> */
        $c5   = { 00 57 49 4E 00 }             /* WIN     */
        $c6   = { 00 63 6D 64 2E 65 78 65 00 } /* cmd.exe */
        $c7   = { 00 49 44 00 }                /* ID      */ 
        $c8   = { 00 72 65 6D 00 }             /* rem     */
        $d1   = "\\SEA.pdb"
        $d2   = "\\mas.pdb"
        $s1  = "Connecting to the server..."
        $s2  = "cmd.exe /c sc stop sea & sc start sea"
        $s3  = "SYSTEM\\CurrentControlSet\\services\\SEA\\Parameters"
        $s4  = "RecvWrit()-Read_Sock-Failed"
        $s5  = "ReadPipeSendSock()"
    condition:
        (4 of ($c*) and (2 of ($s*) or any of ($d*))) or (5 of ($c*) and any of ($s*))
}
