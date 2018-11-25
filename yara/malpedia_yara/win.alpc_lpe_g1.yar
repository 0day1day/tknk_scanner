rule win_alpc_lpe_g1 {
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
        /*
        status = RpcStringBindingComposeW(L"c8ba73d2-3d55-429c-8e9a-c44f006f69fc", L"ncalrpc", 
        nullptr, nullptr, nullptr, &StringBinding);
        */
        $s1 = "c8ba73d2-3d55-429c-8e9a-c44f006f69fc" wide
        $s2 = "ncalrpc" wide 

    condition:
        all of them
}
