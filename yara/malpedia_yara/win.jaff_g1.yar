rule win_jaff_g1 {
    meta:
        author="mak"
        function="get_config"
        malpedia_version = "20170620"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $api0="GetSystemPowerStatus"
        $api1="InternetOpenUrlW"
        $api2="FindResourceW"
        $api3="Advapi32.dll"
        $xor_str = {8A 1C 10 8A 8E [4] 32 CB 74 04 88 0A EB 02}

    condition:
        all of them
}
