rule win_andromeda_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>, Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        contribution = "Slavo Greminger, SWITCH-CERT"
        date = "2015-05-12"
        description = "should catch most versions of andromeda"
        malpedia_version = "20170612"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $cnc_msg_v3_0 = "id:%lu|bid:%lu|os:%lu|la:%lu|rg:%lu" ascii
        $cnc_msg_v3_1 = "id:%lu|tid:%lu|err:%lu|w32:%lu" ascii

        $cnc_msg_v2_0 = "id:%lu|bid:%lu|bv:%lu|os:%lu|la:%lu|rg:%lu" ascii
        $cnc_msg_v2_1 = "id:%lu|tid:%lu|res:%lu" ascii

        $cnc_msg_v1_0 = "id:%lu|bid:%lu|bv:%lu|sv:%lu|pa:%lu|la:%lu|ar:%lu" ascii
        $cnc_msg_v1_1 = "id:%lu|tid:%lu|result:%lu" ascii

        // added 2015-05-12 in order to detect version 2.10
        $cnc_msg_v2_10_0 = "{\"id\":%lu,\"bid\":%lu,\"os\":%lu,\"la\":%lu,\"rg\":%lu" ascii
        $cnc_msg_v2_10_1 = "{\"id\":%lu,\"tid\":%lu,\"err\":%lu,\"w32\":%lu}" ascii

        $piv_get_token = { 0D 00 10 00 00  A3 [4]  39 ?? ??  74 0A  0D 00 00 01 00  A3 }
        $piv_token_str = "S-1-5-32-544"
        $piv_key_policy = "D:(A;;KA;;;WD)" wide ascii
        $piv_connection_test = "update.microsoft.com" wide ascii  // online check

        // loader
        $loader_0 = { FF 56 ?? 0F AF D8 81 E7 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 0F 84 }
        $loader_1 = { 8B 45 F0 8B 4d 14 3B 41 18 }

        // anti analysis checks may be over-suspicious, this are strings to detect the unwrapper
        $packed_0 = "kernel32.dll" wide
        $packed_rc4_init_loop = { AB 2D 04 04 04 04 E2 F8 }
        $packed_start_decrypt = { E8 00 00 00 00 58 2D ?? ?? ?? ?? 05 ?? ?? ?? ?? 6A 00 50 E8 }
        $packed_qemu = { 81 BD ?? ?? ?? ?? 76 62 6F 78 }
        $packed_vbox = { 81 BD ?? ?? ?? ?? 71 65 6D 75 }

    condition:
        ((any of ($cnc_msg_*)) and (2 of ($piv_*))) or (all of ($packed_*)) or (all of ($loader_*))
}
