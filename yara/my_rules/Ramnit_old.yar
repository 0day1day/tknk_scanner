/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule ramnit_cookie_module
{
    strings:
        $cookie1 = "IE Cookies\x00FireFox Cookies\\Profile %d\\cookies.txt\x00"
        $cookie2 = "Chrome\\Cookies\x00Chrome\\Extension Cookies\x00Opera\\Profile %d\\cookies4.dat\x00"

    condition:
        any of them
}

rule ramnit_ftp_grabber_module
{
    meta:
        tags = "Ramnit"
    strings:
        $ftplist = "NetDrive\x00\x00\x00\x00FtpControl\x00\x00\x00\x00\x00\x0032bit FTP\x00"
    condition:
        $ftplist
}

rule ramnit_ftp_server_module
{
    meta:
        tags = "Ramnit"
    strings:
        $ftpmsg = "220 220 RMNetwork FTP\x00"
    condition:
        $ftpmsg
}

rule ramnit_hooker_module
{
    meta:
        tags = "Ramnit"
    strings:
        //W.e.b.D.a.t.a.F.i.l.t.e.r.s...W.e.b.F.a.k.e.s.
        $webfilter = "W\x00e\x00b\x00D\x00a\x00t\x00a\x00F\x00i\x00l\x00t\x00e\x00r\x00s\x00\x00\x00W\x00e\x00b\x00F\x00a\x00k\x00e\x00s\x00"
        //<.*.>.<.s.c.r.i.p.t.*.>.*.<./.s.c.r.i.p.t.>.
        $script = "<\x00*\x00>\x00<\x00s\x00c\x00r\x00i\x00p\x00t\x00*\x00>\x00*\x00<\x00/\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00"
    condition:
        all of them
}

rule ramnit_vnc_module
{
    meta:
        tags = "Ramnit"
    strings:
        //".%.s.". .%.s...".%.s.".....RFB ....RFB 003.003..
        $rfb = "\"\x00%\x00s\x00\"\x00 \x00%\x00s\x00\x00\x00\"\x00%\x00s\x00\"\x00\x00\x00\x00\x00RFB \x00\x00\x00\x00RFB 003\x2E003\x0A\x00"
    condition:
        $rfb
}

rule ramnit_drivescan_module
{
    meta:
        tags = "Ramnit"
   strings:
       /*
       8B 75 08 mov esi, [ebp+pattern]
       8A 06 mov al, [esi]
       33 DB xor ebx, ebx
       57 push edi
       3A C3 cmp al, bl
       74 ?? jz short ??
       3C 2A cmp al, '*'
       74 ?? jz short ??
       3C 3F cmp al, '?'
       74 ?? jz ??
       0F BE C0 movsx eax, al
       50 push eax
       E8 ?? ?? ?? ?? call toupper
       8B 7D 0C mov edi, [ebp+path]
       8B D8 mov ebx, eax
       0F BE 07 movsx eax, byte ptr [edi]
       50 push eax
       E8 ?? ?? ?? ?? call toupper
       59 pop ecx
       */
       $comparefn = {8B 75 08 8A 06 33 DB 57 3A C3 74 ?? 3C 2A 74 ?? 3C 3F 74 ?? 0F BE C0 50 E8 ?? ?? ?? ?? 8B 7D 0C 8B D8 0F BE 07 50 E8 ?? ?? ?? ?? 59}
   condition:
       $comparefn
}
