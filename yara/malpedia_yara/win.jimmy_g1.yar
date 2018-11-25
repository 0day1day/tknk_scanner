rule win_jimmy_g1 {
    meta:
        author = "Daniel Plohmann"
        malpedia_version = "20171001"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $jimmy_api_obfuscation = { 55 8b ec 51 68 [4] 6a 01 e8 [4] 59 59 }

    condition:
        #jimmy_api_obfuscation > 10
}

