rule win_breakthrough_loader_g0 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20180919"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $str_taskd = "hwid=%d&taskid=%d&status=%d"
        $str_tasks = "hwid=%s&taskid=%d&status=%d"
        $str_osd   = "hwid=%d&os=&build="
        $str_oss   = "hwid=%s&os=%s&build="
        $str_delbots      = "deletebots"
        $str_updatebots   = "updatebots"
        $str_nosniff      = "nosniff"
        $str_exclusiv     = "\\Exclusiv\\"
        $str_breakthrough = "\\хп-пробив\\"

    condition:
        4 of them
}
