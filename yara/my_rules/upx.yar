rule UPX_Packer
{
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"

    condition:
        $upx0 and $upx1
}
