rule UPX_Packer
{
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"

    condition:
        all of them
}
