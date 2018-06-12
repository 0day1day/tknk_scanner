rule Ursnif_report_variant_memory
{
    meta:
        description = "Ursnif"
        author = "Fidelis Cybersecurity"
        reference = "New Ursnif Variant Targeting Italy and U.S - June 7, 2016"

    strings:
        $isfb1 = "/data.php?version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s"
        $isfb2 = "client.dll"
        $ursnif1 = "soft=1&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
        $a1 = "grabs="
        $a2 = "HIDDEN"
        $ursnif2 = "/images/"
        $randvar = "%s=%s&"
        $specialchar = "%c%02X" nocase
        $serpent_setkey = {8b 70 ec 33 70 f8 33 70 08 33 30 33 f1 81 f6 b9 79 37 9e c1 c6 0b 89 70 08 41 81 f9 84 [0-3] 72 db}
    condition:
        7 of them
}

rule Ursnif_mailslot
{
    strings:
        $s1= "\\\\.\\mailslot\\msl0" 
        $s2= "memcpy"
        $s3= "memset"

    condition:
        all of them
}

rule Ursnif_Device
{
    strings:
        $s1= "UNKNOWN"
        $s2= "SCSI"
        $s3= "ATAPI"
        $s4= "IEEE 1394"
        $s5= "FIBRE"
        $s6=  "Direct Access Device"
        $s7=  "Tape Device"
        $s8=  "Printer Device"
        $s9=  "Processor Device"
        $s10=  "WORM Device"
        $s11=  "CDROM Device"
        $s12=  "Scanner Device"
        $s13=  "Optical Disk"
        $s14=  "Media Changer"
        $s15=  "Comm. Device"
        $s16=  "ASCIT8"
        $s17=  "Array Device"
        $s18=  "Enclosure Device"
        $s19=  "RBC Device"
        $s20=  "Unknown Device"
        $s21= "RAID"

    condition:
        all of them
}
