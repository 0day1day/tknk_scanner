/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule win_sakula_rat_w1 {
    meta:
        description = "Sakula v1.1"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/Sakula.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "=%s&type=%d"
        $m4 = "?photoid="
        $m5 = "iexplorer"
                $m6 = "net start \"%s\""
        $v1_1 = "MicroPlayerUpdate.exe"

    condition:
        all of them
}

