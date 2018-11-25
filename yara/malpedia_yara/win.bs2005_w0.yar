import "pe"

rule win_bs2005_w0 {
    meta:
        description = "Detects malware from APT 15 report by NCC Group"
        author = "Florian Roth"
        reference = "https://goo.gl/HZ5XMN"
        date = "2018-03-10"
        hash1 = "750d9eecd533f89b8aa13aeab173a1cf813b021b6824bc30e60f5db6fa7b950b"
        malpedia_version = "20180312"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "AAAAKQAASCMAABi+AABnhEBj8vep7VRoAEPRWLweGc0/eiDrXGajJXRxbXsTXAcZAABK4QAAPWwAACzWAAByrg==" fullword ascii
        $x2 = "AAAAKQAASCMAABi+AABnhKv3kXJJousn5YzkjGF46eE3G8ZGse4B9uoqJo8Q2oF0AABK4QAAPWwAACzWAAByrg==" fullword ascii

        $a1 = "http://%s/content.html?id=%s" fullword ascii
        $a2 = "http://%s/main.php?ssid=%s" fullword ascii
        $a3 = "http://%s/webmail.php?id=%s" fullword ascii
        $a9 = "http://%s/error.html?tab=%s" fullword ascii

        $s1 = "%s\\~tmp.txt" fullword ascii
        $s2 = "%s /C %s >>\"%s\" 2>&1" fullword ascii
        $s3 = "DisableFirstRunCustomize" fullword ascii
    condition:
        1 of ($x*) or 2 of them
}
