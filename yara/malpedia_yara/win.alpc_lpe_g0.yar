rule win_alpc_lpe_g0 {
    meta:
        description = "Identify potential XPS Sched 0day cradles"
        author = "blevene @upperCase, Chronicle Security"
        version = "1.0"
        date = "08-28-2018"
        TLP = "GREEN"
        reference = "https://github.com/SandboxEscaper/randomrepo/blob/master/PoC-LPE.rar"
        malpedia_version = "20180907"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:

        //these are all unicode strings 
        $s1 = "D:(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)" wide

    condition:
        all of them
}
