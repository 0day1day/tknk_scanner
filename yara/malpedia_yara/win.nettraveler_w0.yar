/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule win_nettraveler_w0 {
    meta:
        description = "Identifiers for NetTraveler DLL"
        author = "Katie Kleemola"
        last_updated = "2014-05-20"
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        //network strings
        $n1 = "?action=updated&hostid="
        $n2 = "travlerbackinfo"
        $n3 = "?action=getcmd&hostid="
        $n4 = "%s?action=gotcmd&hostid="
        $n5 = "%s?hostid=%s&hostname=%s&hostip=%s&filename=%s&filestart=%u&filetext="

        //debugging strings
        $d1 = "\x00Method1 Fail!!!!!\x00"
        $d2 = "\x00Method3 Fail!!!!!\x00"
        $d3 = "\x00method currect:\x00"
        $d4 = /\x00\x00[\w\-]+ is Running!\x00\x00/
        $d5 = "\x00OtherTwo\x00"

    condition:
        any of them
}

