rule win_karagany_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        date = "2017-08-04"
        malpedia_version = "20170804"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $cmd_0 = "delshedexec"
        $cmd_1 = "exec:thr1"
        $cmd_2 = "downadminexec"
        $s0 = "mmc_install" wide

    condition:
        all of them
}
