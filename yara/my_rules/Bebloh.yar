rule Bebloh
{
    strings:
        $0 = "EXEUPDATE"
        $1 = "INJECTFILE"
        $2 = "www.google.com"
        $3 = "?tver="
        $4 = "&vcmd="
        $5 = "&cc="
        $6 = "&hh="
        $7 = "&ipcnf="
        $8 = "&sckport="
        $9 = "&pros="
        $10 = "&keret="
        $11 = "&email="
        $12 = "auth"
        $13 = ".com"
        $14 = ".net"
        $15 = ".exe"
        $16 = ".lnk"
    condition:
        all of them
}
