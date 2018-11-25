rule win_hermes_w0 {
    meta:
        author = "BAE"
        reference = "https://baesystemsai.blogspot.de/2017/10/taiwan-heist-lazarus-tools.html"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        //in both version 2.1 and sample in Feb
        $s1 = "SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\"
        $s2 = "0419"
        $s3 = "0422"
        $s4 = "0423"
        //in version 2.1 only
        $S1 = "HERMES"
        $S2 = "vssadminn"
        $S3 = "finish work"
        $S4 = "testlib.dll"
        $S5 = "shadowstorageiet"
        //maybe unique in the file
        $u1 = "ALKnvfoi4tbmiom3t40iomfr0i3t4jmvri3tb4mvi3btv3rgt4t777"
        $u2 = "HERMES 2.1 TEST BUILD, press ok"
        $u3 = "hnKwtMcOadHwnXutKHqPvpgfysFXfAFTcaDHNdCnktA" //RSA Key part
    condition:
        all of ($s*) and 3 of ($S*) and 1 of ($u*)
}
