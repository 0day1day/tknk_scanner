rule win_retefe_g0 {
    meta:
        author = "Slavo Greminger, Daniel Stirnimann, SWITCH-CERT"
        comment = "Retefe v4 is based on a javascript; the rule only works on memdumps"
        malpedia_version = "20170619"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $v1_c1 = "ROOT"
        $v1_c2 = "CRYPT_E_EXISTS"
        $v1_c3 = "E_INVALIDARG"
        $v1_a1 = "%s\\%s%s"
        $v1_d1 = "DhcpNameServer"
        $v1_d2 = "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\Interfaces"
        $v1_d3 = "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters"
        $v1_d4 = "ipconfig /flushdn"
        $v1_d5 = "MaxCacheTtl"
        $v1_d6 = "MaxNegativeCacheTtl"
        $v1_d7 = "lanname=%"
        $v1_d8 = "name\"=%lanname%"


        $v2_3_str_1w  = "CONOUT$" wide
        $v2_3_str_1   = "CONOUT$"
        $v2_3_str_2   = "(Get-Process|Select-String -pattern %PROCESSES%).count"
        $v2_3_str_3   = "#32770"
        $v2_3_str_4   = "csrss\x00certutil"
        $v2_3_str_5   = "/Q /T:\"%s\""
        $v2_3_ops_url = { E8 [4] 6A 05 6A ?? E8 [4]  69 C0 ?? ?? 00 00  B? FF FF FF 7F  6A 01  2B ?? E8 }
        $v2_3_ops_QTs = { 83 C0 F0 83 C4 08  8D 48 0C  83 CA FF  F0 0F C1 11  4A 85 D2 }
        $v2_3_ops_sys = { 77 ?? B? 01 00 00 00 2B ?? 03 F? 83 7? ?? ?? 72 0? 8B }

        $v2_mem_cookies = "dir ([system.environment]::GetFolderPath('Cookies')+'\\*.txt')|Get-Content"
        $v2_mem_cookieslow = "dir ([system.environment]::GetFolderPath('Cookies')+'\\Low\\*.txt')|Get-Content"
        $v2_mem_powershellExe = "powershell.exe"
        $v2_mem_powershellGetContent = "Get-Content"
        $v2_mem_powershellSetContent = "Set-Content"
        $v2_mem_powershellProxy = "-notmatch 'network.proxy."
        $v2_mem_certutil = "certutil -addstore -f -user \"ROOT\" \"%FILE%\""


        $v3_mem_vpn = "DEVICE=vpn"
        $v3_mem_phone = "PhoneNumber="
        $v3_mem_ras = "rasdial Intenret %login% %pass% > NUL"


        $v4_mem_proneFP_TypoPort = "Sessions\\1\\Windows\\ApiPortection" wide
        $v4_mem_proneFP_powershellPolicy = "powershell.exe\" -ExecutionPolicy Unrestricted -File \""
        $v4_mem_proneFP_netCvtres = "cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 \"/OUT:"
        $v4_mem_proneFP_netWin = "Winsta0\\Default"
        $v4_mem_proneFP_netCrypt = "Microsoft Base Cryptographic Provider v1.0"

        $v4_mem_ps_cert1a = "@;\x0d\x0a[Win32]::Start();\x0d\x0a}\x0d\x0aConfirmCert"
        $v4_mem_ps_cert1b = "function ConfirmCert{\x0d\x0aAdd-Type @\""
        $v4_mem_ps_cert2 = "const int BM_CLICK = 0x00F5;"
        $v4_mem_ps_cert3a = "hWnd = FindWindow(\"#32770\","
        $v4_mem_ps_cert3b = "hWnd = SearchForWindow(\"#32770\","
        $v4_mem_ps_cert4a = "GetExeName(hWnd).Contains(\"csrss\") || GetExeName(hWnd).Contains(\"certutil\")"
        $v4_mem_ps_cert4b = "sEN.Contains(\"csrss\") || sEN.Contains(\"certutil\")  || sEN.Contains(\"powershell\")"

    condition:
        ( 7 of ($v1_*) ) or
        ( 3 of ($v2_3_str_*) and any of ($v2_3_ops_*) ) or
        ( all of ($v2_mem_cookies*) or all of ($v2_mem_powershell*) or all of ($v2_mem_certutil*) ) or
        ( all of ($v3_mem_*) ) or
        ( 3 of ($v4_mem_proneFP_*)  or 2 of ($v4_mem_ps_cert*) )
}
