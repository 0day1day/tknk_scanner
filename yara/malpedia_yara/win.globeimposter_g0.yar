rule win_globeimposter_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        contributions = "Daniel Plohmann"
        malpedia_version = "20171130"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_cert   = "CertificatesCheck" wide
        $str_read   = "Read___ME.html" wide
        $str_ID      = "{{IDENTIFIER}}"
        $str_rsa    = "rsa_encrypt"
        $str_cmd1   = "vssadmin.exe Delete Shadows /All /Quiet"
        $str_cmd2   = "reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server "
        $str_cmd3   = "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1"

    condition:
        5 of them
}
