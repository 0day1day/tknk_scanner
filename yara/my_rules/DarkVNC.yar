rule DarkVNC
{
    strings:
        $s1 = "#hvnc" wide ascii
        $s2 = "MOZ_DISABLE_CONTENT_SANDBOX" wide ascii
        $s3 = "opera.exe" wide ascii
        $s4 = "chrome.exe" wide ascii
        $s5 = "firefox.exe" wide ascii
        $s6 = "user_pref(\"browser.shell.checkDefaultBrowser\", false);" wide ascii

    condition:
        all of them
}
