rule win_exchange_tool_w0 {
    meta:
        description = "Detects malware from APT 15 report by NCC Group"
        author = "Florian Roth"
        reference = "https://goo.gl/HZ5XMN"
        date = "2018-03-10"
        hash1 = "16b868d1bef6be39f69b4e976595e7bd46b6c0595cf6bc482229dbb9e64f1bce"
        malpedia_version = "20180312"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "\\Release\\EWSTEW.pdb" ascii
        $s2 = "EWSTEW.exe" fullword wide
        $s3 = "Microsoft.Exchange.WebServices.Data" fullword ascii
        $s4 = "tmp.dat" fullword wide
        $s6 = "/v or /t is null" fullword wide
    condition:
        all of them
}
