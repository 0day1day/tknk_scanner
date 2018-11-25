import "pe"

rule win_mosquito_w2 {
    meta:
        description = "Detects malware sample from Turla Mosquito report"
        author = "Florian Roth"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "Logger32.dll" fullword ascii
        $s6 = "lManager::Execute : CPalExceptio" fullword wide
        $s19 = "CCommandSender::operator(" fullword wide
    condition:
        pe.imphash() == "073235ae6dfbb1bf5db68a039a7b7726" or 2 of them
}
