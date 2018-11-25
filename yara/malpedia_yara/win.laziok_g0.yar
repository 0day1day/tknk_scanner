rule win_laziok_g0 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        contribution = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180216"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_name = "aziokl" wide
        $str_av2 = "Kaspersky" wide 
        $str_av3 = "McAfee" wide
        $str_computer = "COMPUTER=" wide
        $str_country = "COUNTRY=" wide
        $str_hwid = "&HWID=" wide
        $str_avname  = "&avname=" wide
        $str_webnavi = "&webnavig=" wide
        $str_gettask = "gettask.php?RUN=" wide
  $str_pipe1 = "|oa:" wide
  $str_pipe2 = "|bi:" wide

        $op_c2conn   = { 7? ??  8B 40 0C  8B 00  8B ?? [0-4]  33 C0  83 [1-2] FF  0F 95 C0  (3?|8?) C? }
        $op_strobf   = { 8B 55 FC  D1 EA  52  (A1 [3] ?? | 8B 45 F8  8B 08 ) 03 4? 0C  5? }
        $op_bin_uniq = { 83 ?? 30 83 ?? 00 83 ?? 02 83 ?? 30 73 }
        $op_int      = { E8 [4] 83 C4 04 89 45 FC 8B 4D 08 83 39 00 75 1E 8B 55 FC  8D 44 12 0A  50  6A 00 }

    condition:
       3 of ($str_*) and 2 of ($op_*)
}
