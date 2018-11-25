rule win_ismdoor_w0 {
	meta:
        author = "Florian Roth"
        reference = "https://goo.gl/urp4CD"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "cmd /u /c WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter" fullword ascii
        $x2 = "cmd /a /c net user administrator /domain >>" fullword ascii
        $x3 = "cmd /a /c netstat -ant >>\"%localappdata%\\Microsoft\\" fullword ascii
        $o1 = "========================== (Net User) ==========================" ascii fullword
    condition:
        1 of them
}
