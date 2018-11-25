rule win_wannacryptor_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
		sample = "b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25"
        malpedia_version = "20170512"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        // ideally, we can leave this one out, otherwise it's a decent backup string for the currently (2017-05-12) active version
        //$crypt_extension = ".wnry"
        
        $libstr_unzip = "unzip 0.15 Copyright 1998 Gilles Vollant"
        $libstr_inflate = "inflate 1.1.3 Copyright 1995-1998 Mark Adler"
        
        // APIs related to ransom activity
        $api_logical_drives = "GetLogicalDrives"
        $api_drive_type = "GetDriveType"
        $api_find_first = "FindFirstFileA"
        $api_find_next = "FindNextFileA"
        $api_crypt_import = "CryptImportKey"
        
        $wry = ".wry"
        
        $rsa2_key = {52 53 41 32 00 08 00 00 01 00 01 00 }
        $disable_shadow_copy_0 = "/c vssadmin delete shadows /all /quiet & wmic shadowcopy delete & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no & wbadmin delete catalog -quiet"
        $disable_shadow_copy_1 = "cmd.exe /c start /b vssadmin.exe Delete Shadows /All /Quiet"
        $disable_shadow_copy_2 = "/c start /b vssadmin.exe Delete Shadows /All /Quiet"

    condition:
       (
        ((all of ($api_*)) or #wry > 5) and 
        1 of ($libstr_*)) and 
        $rsa2_key and 
        (any of ($disable_shadow_copy_*)
       )
}
