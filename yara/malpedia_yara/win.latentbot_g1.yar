rule win_latentbot_g1 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        info = "dropper"
        malpedia_version = "20170530"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $pe_section_1 = "text32"
        $pe_section_2 = "text64"
        $stack_string = { C7 45 ?? ?? 00 ?? 00 }
        
    condition:
        all of ($pe_section_*) and #stack_string > 100
}
