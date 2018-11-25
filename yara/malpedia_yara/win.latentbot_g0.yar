rule win_latentbot_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20170530"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $crypted_str_1 = "49VL870G9BAtC2P"
        $crypted_str_2 = "4BlRErxQhNze"
        $crypted_str_3 = "gtqbK9oveHM"
        
    condition:
        all of them
}
