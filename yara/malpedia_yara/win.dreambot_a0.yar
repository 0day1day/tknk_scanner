rule win_dreambot_a0 {
    meta:
        author = "mak, Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180110"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $str_dropper_1 = "ASCIT8" fullword
        $str_dropper_2 = "IEEE 1394"
        $str_dropper_3 = "Tape Device" fullword

        // Dreambot
        $str_vm_1 = "qemu" fullword
        $str_vm_2 = "vbox" fullword
        $str_vm_3 = "virtual hd" fullword
        $str_vm_4 = "vmware" fullword
        // often, but not exclusively
        $str_vm_5 = "c:\\321.txt" fullword
        $str_vm_6 = "c:\\vodka.txt" fullword

    condition:
        7 of them
}
