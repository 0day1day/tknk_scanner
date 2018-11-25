rule win_doublepulsar_w0 {
	meta:
		author = "Florian Roth"
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
   strings:
      $x1 = "[+] Ping returned Target architecture: %s - XOR Key: 0x%08X" fullword ascii
      $x2 = "[.] Sending shellcode to inject DLL" fullword ascii
      $x3 = "[-] Error setting ShellcodeFile name" fullword ascii
   condition:
      1 of them
}
