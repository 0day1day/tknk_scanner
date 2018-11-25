rule win_flawedammyy_g1 {
    meta:
        author = "CCIRC"
        description = "In memory rule to detect FlawedAmmyy RAT"
        malpedia_version = "20180529"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        $string1 = "ammyy"
        $string2 = "x:\\prj\\ammy\\svn\\ammyygeneric\\target\\TrFmFileSys.h"
        $string3 = "priv="
        $string4 = "cred="
        $string5 = "pcname="
        $string6 = "avname="
        $string7 = "build_time="
        $string8 = "card="
    condition:
           all of them
}
