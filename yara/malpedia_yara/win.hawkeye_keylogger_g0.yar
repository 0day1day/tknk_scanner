rule win_hawkeye_keylogger_g0 {
  meta:
      author = "Various authors / Slavo Greminger, SWITCH-CERT"
      malpedia_version = "20171121"
      malpedia_license = "CC BY-NC-SA 4.0"
      malpedia_sharing = "TLP:GREEN"

    strings:
        $he_DKeylogger = "HawkEye.Keylogger" wide ascii
        $he_SKeylogger = "HawkEye Keylogger" wide ascii
        $he_UKeylogger = "HawkEye_Keylogger" wide ascii
        $he_Keylogger  = "HawkEyeKeylogger" wide ascii

        // reborn
        $str_HawkEye_reborn = "HawkEye Keylogger - Reborn" wide ascii
        $str_Logs1   = "Logs - {1} \\ {2}" wide ascii
        $str_Logs2   = "Logs{0}{2} \\ {3}{0}{0}{4}" wide ascii
        $str_Caption = "{0}{0}============={1} {2}============={0}{0}" wide ascii

    condition:
        2 of them
}
