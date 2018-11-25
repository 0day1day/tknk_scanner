rule win_nautilus_w0 {
    meta:
        description = "Rule for detection of Nautilus based on assembly code for a modified RC4 loop"
        author = "NCSC UK"
        hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
        malpedia_version = "20180226"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $rc4_loop = {42 0F B6 14 04 41 FF C0 03 D7 0F B6 CA 8A 14 0C 43 32 14 13 41 88 12 49 FF C2
        49 FF C9}
        $rc4_key = {31 42 31 34 34 30 44 39 30 46 43 39 42 43 42 34 36 41 39 41 43 39 36 34 33 38
        46 45 45 41 38 42}
        $string_0 = "nautilus-service.dll" ascii
        $string_1 = "oxygen.dll" ascii
        $string_2 = "config_listen.system" ascii
        $string_3 = "ctx.system" ascii
        $string_4 = "3FDA3998-BEF5-426D-82D8-1A71F29ADDC3" ascii
        $string_5 = "C:\\ProgramData\\Microsoft\\Windows\\Caches\\{%s}.2.ver0x0000000000000001.db"
    condition:
        ($rc4_loop and $rc4_key) or (all of ($string_*)) 
}
