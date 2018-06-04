rule AZORult_2 {
    strings:
        $s0 = "Passwords.txt"
        $s1 = "CookieList.txt"
        $s2 = "NSS_Init"
        $s3 = "NSS_Shutdown"
        $s4 = "PK11_GetInternalKeySlot"
        $s5 = "PK11SDR_Decrypt"
        $s6 = "PK11_FreeSlot"
        $s7 = "PK11_Authenticate"
        $s8 = "Q3JlYXRlVG9vbGhlbHAzMlNuYXBzaG90"
        $s9 = "UHJvY2VzczMyRmlyc3RX"
        $s10 = "a2VybmVsMzIuZGxs"
        $s11 = "UHJvY2VzczMyTmV4dFc="
        $s12 = "U29mdHdhcmVcVmFsdmVcU3RlYW0="
        $s13 = "U3RlYW1QYXRo"
        $s14 = "XHNzZm4q"
        $s15 = "XENvbmZpZ1wqLnZkZg=="
        $s16 = "XENvbmZpZ1w="
        $s17 = "PsiPlus"
        $s18 = "Pidgin"
        $s19 = "RGlzcGxheVZlcnNpb24="
        $s20 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxsXA=="
        $s21 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxs"
        $s22 = "RGlzcGxheU5hbWU="
        $s23 = "UHJvY2Vzc29yTmFtZVN0cmluZw=="
        $s24 = "SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA=="
        $s25 = "SELECT host, path, isSecure, expiry, name, value FROM moz_cookies"
        $s26 = "SELECT host_key, name, encrypted_value, value, path, secure, expires_utc FROM cookies"
        $s27 = "SELECT host_key, name, name, value, path, secure, expires_utc FROM cookies"
        $s28 = "SELECT fieldname, value FROM moz_formhistory"
        $s29 = "SELECT name, value FROM autofill"
        $s30 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted value FROM credit_cards"
        $s31 = "System.txt"
        $s32 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $s33 = "ST234LMUV56CklAopq78Brstuvwxyz01NOPQRmGHIJKWXYZabcdefgDEFhijn9+/" wide ascii // Azorult custom base64-like alphabet
        $w0 = "mbhd.spvchain" wide
        $w1 = "mbhd.yaml" wide
        $w2 = "electrum.dat" wide
        $w3 = "mbhd.checkpoints" wide
        $w4 = "wallet_path" wide
        $w5 = "%APPDATA%\\MultiBitHD" wide
        $w6 = "Software\\Bitcoin\\Bitcoin-Qt" wide
        $w7 = "\\.wallet" wide
        $w8 = "mbhd.wallet.aes" wide
        $w9 = "\\BitcoinBitcoinQT\\wallet.dat" wide
        $w10 = ".address.txt" wide
        $w11 = "\\electrum.dat" wide
        $w12 = "\\MultiBitHD\\" wide
        $w13 = "\\Monero\\" wide
        $w14 = "Chrome" wide ascii
        $w15 = "YandexBrowser" wide ascii
        $w16 = "Opera" wide ascii
        $w17 = "Firefox" wide ascii
        $w18 = "Orbitum" wide ascii
        $w19 = "Chromium" wide ascii
        $w20 = "Amigo" wide ascii
        $w21 = "Outlook" wide ascii
        $w22 = "FileZilla" wide ascii
        $w23 = "WinSCP" wide ascii
        //$w24 = "Thunderbird" wide ascii
        $w25 = "360Browser" wide ascii
        $w26 = "Bromium" wide ascii
        $w27 = "InternetMailRu" wide ascii
        $w28 = "Bromium" wide ascii
        $w29 = "Nichrome" wide ascii
        $w30 = "RockMelt" wide ascii
        $w31 = "Skype" wide ascii
        $w32 = "Steam" wide ascii
        $w33 = "_CC.txt" wide ascii
        $constant1 = {85 C0 74 40 85 D2 74 31 53 56 57 89 C6 89 D7 8B 4F FC 57} // Azorult grabs .txt and .dat files from Desktop
        $constant2 = {68 ?? ?? ?? ?? FF 75 FC 68 ?? ?? ?? ?? 8D 45 F8 BA 03 00} // Portion of code from Azorult self-delete function
    condition:
        all of them
}




