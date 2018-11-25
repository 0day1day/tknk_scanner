import "pe"

rule win_sierras_w0 {
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		info = "charlie component"
        hash = "f4750e1d82b08318bdc1eb6d3399dee52750250f7959a5e4f83245449f399698.bin"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/SierraCharlie.yar"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	strings:
	/*
		8B 0D 50 A7 56 00  mov     ecx, DnsFree
		81 F6 8C 3F 7C 5E  xor     esi, 5E7C3F8Ch
		6A 01              push    1               ; _DWORD
		50                 push    eax             ; _DWORD
		85 C9              test    ecx, ecx
		74 3A              jz      short loc_40580B
		FF D1              call    ecx ; DnsFree
	*/

	$dnsResolve = {
			8B 0D 50 A7 56 00 
			81 F6 8C 3F 7C 5E 
			6A 01 
			50 
			85 C9 
			74 3A 
			FF D1 
		}
		
	$file1 = "wmplog21t.sqm"
	$file2 = "wmplog15r.sqm"
	$file3 = "wmplog09c.sqm"
		

	condition:
		$dnsResolve in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or 2 of ($file*)
}
