/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule win_cybergate_w0 {

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		contributors = "Daniel Plohmann"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/CyberGate"
        malpedia_version = "20170517"
        malpedia_license = "GNU-GPLv2"
        malpedia_sharing = "TLP:WHITE"

	strings:
		$string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$string3 = "EditSvr"
		$string4 = "TLoader"
		$string5 = "Stroks"
		$string6 = "####@####"
		$res1 = "XX-XX-XX-XX"
		$res2 = "CG-CG-CG-CG"
		
		$command_0 = "limpasclipboard"
		$command_1 = "shellativar"
		$command_2 = "configuracoesdoserver"
		$command_3 = "finalizarconexao"

	condition:
		(all of ($string*) or any of ($res*)) or (all of ($command_*))
}
