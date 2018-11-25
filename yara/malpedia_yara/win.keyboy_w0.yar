import "pe"

rule win_keyboy_w0 {
    meta:
        author = "Florian Roth"
        reference = "http://www.pwc.co.uk/issues/cyber-security-data-privacy/research/the-keyboys-are-back-in-town.html"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $x1 = "reg add HKLM\\%s\\Parameters /v ServiceDll /t REG_EXPAND_SZ /d \"%s\" /f" fullword ascii
        $x3 = "Internet using \\svchost.exe -k  -n 3" fullword ascii
        $x4 = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v SFCDisable /t REG_DWORD /d 4 /f" fullword ascii

        $s1 = "sc create %s binpath= \"%s\" Type= share Start= auto DisplayName= \"%s\"" fullword ascii
        $s2 = "ExecCmd:%s" fullword ascii
        $s3 = "szCommand : %s" fullword ascii
        $s4 = "Current user is a member of the %s\\%s group" fullword ascii
        $s5 = "icacls %s /grant administrators:F" fullword ascii
        $s6 = "Ping 127.0.0.1 goto Repeat" fullword ascii
        $s7 = "Start MoveFile %s -> %s" fullword ascii
        $s8 = "move %s\\dllcache%s %s\\dllcache\\%s" fullword ascii
        $s9 = "%s\\cmd.exe /c \"%s\"" fullword ascii
    condition:
        pe.imphash() == "68f7eced34c46808756db4b0c45fb589" or
        ( pe.exports("Insys") and pe.exports("Inuser") and pe.exports("SSSS") ) or
        1 of ($x*) or
        4 of them
}
