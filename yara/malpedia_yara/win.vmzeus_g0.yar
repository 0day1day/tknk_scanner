rule win_vmzeus_g0 {
    meta:
        author	 = "mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $VMZEUS_GetRC6_Key = { 81 ec b0 00 00 00 }
        $VMZEUS_GetBaseConfig = { 0f b6 00 8d 4? [1-2] ff 14 85 ?? ?? ?? ?? 84 c0 7?}
        $config_decrypt = { 81 78 02 3F 10 00 00}
        // $reverse_key = { 8A ?? ?? [4] ?? 40 ?? ?? ?? ?? 75 F1 }
        
    condition:
        2 of them
}
