rule win_codekey_w0 {
    meta:
	    author = "RSA Research"
	    description = "detects Win32 files signed with stolen code signing key used in Kingslayer attack" 
	    reference = "http://firstwat.ch/kingslayer"
	    hash0 = "fbb7de06dcb6118e060dd55720b51528"
	    hash1 = "3974a53de0601828e272136fb1ec5106"
	    hash2 = "f97a2744a4964044c60ac241f92e05d7"
	    hash3 = "76ab4a360b59fe99be1ba7b9488b5188"
	    hash4 = "1b57396c834d2eb364d28eb0eb28d8e4"
	    malpedia_info = "2017-02-20 modified to also have this rule match on memory dumps - part of the certificate is otherwise truncated while loading"
        malpedia_version = "20170220"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
	    $val0 = "vLog Service error while sending email" wide
	    $ven0 = { 41 6C 74 61 69 72 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 }
    condition:
	    uint16(0) == 0x5A4D and $val0 and $ven0
}
