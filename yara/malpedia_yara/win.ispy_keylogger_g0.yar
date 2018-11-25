rule win_ispy_keylogger_g0 {
    meta:
        author = "Various authors / Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20171121"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $spy_DKeylog = "iSpy.Keylogger" wide ascii
        $spy_SKeylog = "iSpy Keylogger" wide ascii
        $spy_UKeylog = "iSpy_Keylogger" wide ascii
        $spy_Keylog  = "iSpyKeylogger" wide ascii

        $str_ClipboardLogger = "*********** Clipboard Logger ***********" wide ascii
        $str_ScreenshotLogger = "*********** Screenshot Logger ***********" wide ascii
        $str_Error = "[iSpy Keylogger - Error]" wide ascii

        $str_Soft = "iSpySoft" wide ascii
        // shared with gear informer
        $str_rva     = "5D38EBE25C05C7DB92A7003B08B1539A2E1E0406"

    condition:
        2 of them
}
