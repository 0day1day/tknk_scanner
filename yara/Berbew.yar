rule Berbew
{
    strings:
        $0 = "kkq-vx"
        $1 = "InProcServer32"
        $2 = "CLSID"
        $3 = "ThreadingModel"

    condition:
        all of them
}
