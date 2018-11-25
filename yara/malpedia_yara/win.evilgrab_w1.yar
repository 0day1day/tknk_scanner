/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule win_evilgrab_w1 {
    meta:
        description = "Vidgrab Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/Vidgrab.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "IDI_ICON5" wide ascii
        $s2 = "starter.exe"
        $s3 = "wmifw.exe"
        $s4 = "Software\\rar"
        $s5 = "tmp092.tmp"
        $s6 = "temp1.exe"
        
    condition:
       3 of them
}
