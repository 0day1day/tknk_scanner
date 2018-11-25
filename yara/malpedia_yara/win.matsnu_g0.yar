rule win_matsnu_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>, Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de"
		date = "2014-08-13"
		sample = "unpacked: 3c3f319abe561bbbed004601b1406852"
        malpedia_version = "20170605"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $cnc_urls = "BASEURL"                    // command
        
        $rsa = "RSA1"     // key for C&C encryption, static since a year or so
        
        $rc4key = "6FFwof@fo1#049SfkxZ"
        
        $bot_dlllist = "dlllist=%s"             // bot request string
        $bot_proclist = "proclist=%s"           // bot request string
        $bot_aes = "AES=%s"                     // bot request string
        $bot_idt = "idt=%u&code=%u"             // bot request string
        
        $older_killtask = "TASKKILL /F /PID %u"
        $older_uninstall_reg = "reg.exe delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /f /v \"{%08x-%04x-xxx}\""
        $older_info_string = "id=%s&ver=%s&cvr=%u&threadid=%u&lang=0x%04X&os=%s&%s"
        $older_info = "Adobe Acrobat Reader that is running cannot be used to view PDF files in a web browser"
        $older_http_client_info = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.0.2914)"
        $older_http_content = "Content-Type: application/x-www-form-urlencoded" 
        
    condition:
        $cnc_urls and ($rc4key or ($rsa and (all of ($bot_*)))) or (2 of ($older_*))
}
