rule win_gratem_w0 {
    meta:
        author = "Omri AT Minerva Labs"
        date = "2018-08-21"
        sample_filetype = "exe"
        yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
        malpedia_version = "20180822"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $string0 = "KERNEL32.DLL" wide
        $string1 = "AAFFf;"
        $string2 = "3.3n3x3"
        $string3 = "%Mgr.RhY4RfE5Qd:f"
        $string4 = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
        $string5 = "d1p1v1{1"
        $string6 = "UUjPQW"
        $string7 = "5$595@5T5[5"
        $string8 = "urn:schemas-microsoft-com:asm.v3"
        $string9 = "  </trustInfo>"
        $string10 = "                                 H" wide
        $string11 = "asInvoker"
        $string12 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled ("
    condition:
        9 of them
}
