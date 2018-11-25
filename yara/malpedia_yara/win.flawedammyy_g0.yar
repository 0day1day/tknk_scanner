rule win_flawedammyy_g0 {
   meta:
       author = "Slavo Greminger, SWITCH-CERT"
       comment = "super simple rule with room for improvement"
       malpedia_version = "20180525"
       malpedia_license = "CC BY-NC-SA 4.0"
       malpedia_sharing = "TLP:GREEN"

   strings:
       $ammyy   = "%s\\AMMYY"
       $str_set = "settings3.bin" wide ascii nocase

   condition:
       all of them
}
