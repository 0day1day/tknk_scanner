rule Bunitu
{
    meta:
        author = "nao_sec"
    strings:
        $p1 = "SYSTEM\\ControlSet001\\Services\\MBAMProtector"
        $mutex1 = "TEKL1AFHJ3"
        $mutex2 = "GJLAAZGJI156R"
        $mutex3 = "F-DAH77-LLP"
        $mutex4 = "flowblink90x33"
        $mutex5 = "OPLXSDF19WRQ"
        $mutex6 = "PLAX7FASCI8AMNA"
        $mutex7 = "OLZTR-AFHK11"
        $mutex8 = "AhY93G7iia"
        $mutex9 = "J8OSEXAZLIYSQ8J"
        $mutex10 = "A9MTX7ERFAMKLQ"
        $mutex11 = "VSHBZL6SWAG0C"
        $mutex12 = "TXA19EQZP13A6JTR"
        $mutex13 = "FNZIMLL1"
        $mutex14 = "IGBIASAARMOAIZ"
        $mutex15 = "LXCV0IMGIXS0RTA1"
        $mutex16 = "RGT70AXCNUUD3"
        $mutex17 = "A9ZLO3DAFRVH1WAE"
        $mutex18 = "DRBCXMtx"
        $mutex19 = "MKS8IUMZ13NOZ"
        $mutex20 = "BSKLZ1RVAUON"
        $mutex21 = "NLYOPPSTY"
        $mutex22 = "FURLENTG3a"
        $mutex23 = "I-103-139-900557"
        $mutex24 = "I106865886KMTX"
        $mutex25 = "B81XZCHO7OLPA"
        $mutex26 = "FstCNMutex"
    condition:      
        all of them
}
