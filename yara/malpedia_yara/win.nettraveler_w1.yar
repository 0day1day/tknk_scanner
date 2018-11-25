/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule win_nettraveler_w1 {
    meta:
        description = "Identifiers for netpass variant"
        author = "Katie Kleemola"
        last_updated = "2014-05-29"
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $exif1 = "Device Protect ApplicatioN" wide
        $exif2 = "beep.sys" wide //embedded exe name
        $exif3 = "BEEP Driver" wide //embedded exe description

        $string1 = "\x00NetPass Update\x00"
        $string2 = "\x00%s:DOWNLOAD\x00"
        $string3 = "\x00%s:UPDATE\x00"
        $string4 = "\x00%s:uNINSTALL\x00"

    condition:
        all of ($exif*) or any of ($string*)
}
