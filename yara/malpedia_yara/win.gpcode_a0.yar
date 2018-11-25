rule win_gpcode_a0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "2018-02-09"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings: 
        $res_cfg = "CFG" wide
        /* match the config decryption routine (16 byte static XOR)
        * cmp edx, 0x10
        * jnz
        * xor edx, edx
        * lodsb
        * xor al, ...
        */
        $decrypt_cfg = { 83 FA 10 75 02 33 d2 ac 32}
        $wallpaper_0 = "wall"
        $wallpaper_1 = ".bmp"
        
    condition:
       all of them
}
