rule win_netwire_g0 {
    meta:
        author= "mak"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $s0="[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" ascii fullword
        $s1="[Backspace]" ascii fullword
        $s2="[Enter]" ascii fullword
        $s3="[Tab]" ascii fullword
        $s4="[Arrow Left]" ascii fullword
        $s5="[Arrow Up]" ascii fullword
        $s6="[Arrow Right]" ascii fullword
        $s7="[Arrow Down]" ascii fullword
        $s8="[Home]" ascii fullword
        $s9="[Page Up]" ascii fullword
        $s10="[Page Down]" ascii fullword
        $s11="[End]" ascii fullword
        $s12="[Break]" ascii fullword
        $s13="[Delete]" ascii fullword
        $s14="[Insert]" ascii fullword
        $s15="[Print Screen]" ascii fullword
        $s16="[Scroll Lock]" ascii fullword
        $s17="[Caps Lock]" ascii fullword
        $s18="[Alt]" ascii fullword
        $s19="[Esc]" ascii fullword
        $s20="[Ctrl+%c]" ascii fullword
        $s21="[%s]" ascii fullword
        $decode_data={5? 81 EC 28 01 00 00 8D ?C 24 18 89 ?C 24 C7 44 24 08 10 00 00 00 C7 44 24 }//04 34 34 41 00}
        
    condition:
        10 of them
}
