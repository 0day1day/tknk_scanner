rule win_latentbot_g2 {
    meta:
        author="kamil.frankowicz@cert.pl"
        malpedia_version = "20171218"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $encrypted_plugins_reg_loc = "YRjMiR5pJQ2BYQGnxrtHJr/rc1ldUMq+LwntFlv2clCGXRO+WLP"
        $encrypted_autostart_reg_loc = "YRjMiR5pJQ2BS01054IZ+IU8u00RCk2L9tm+lACTf28OI7vow9xZfWqV7V0q"
        $encrypted_id_reg_loc = "YRjMiR5pJQ2BeUoQ648el9DVFta9CWKqhycjWD"
        $decrypt_strings_and_call = { 89 ?? 8D [2] B8 [4] E8 [4] 8D [2] 50 8D [2] B8 [4] E8 [4] 8B [2] 58 E8 [4] 8B [2] 8B ?? E8 [4] E8 [4] EB ?? }
        $encryption_decryption_core = { 88 [3] 8B [2] 0F [4] 66 [2] 66 [2] 6D CE 66 ?? BF 58 }
        $lookup_table = { 3E 00 00 00 3F 34 35 36 37 38 39 3A 3B 3C 3D [8] 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 }
        $lookup_table_byte_shift = { C1 ?? 06 [14] C1 ?? 0C [14] C1 ?? 12 }

    condition:
        4 of ($encrypted_id_reg_loc, $encrypted_autostart_reg_loc, $encrypted_plugins_reg_loc, $lookup_table_byte_shift, $lookup_table, $encryption_decryption_core) and #decrypt_strings_and_call > 20
}
