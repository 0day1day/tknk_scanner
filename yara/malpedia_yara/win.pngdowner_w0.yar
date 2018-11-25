rule win_pngdowner_w0 {
    meta: 
        description = "PUTTER PANDA - PNGDOWNER"
        date = "2014-03-30" version = "1.0"
        in_the_wild = true
        copyright = "CrowdStrike, Inc."
        actor = "PUTTER PANDA"
        source = "https://www.iocbucket.com/iocs/7f7999ab7f223409ea9ea10cff82b064ce2a1a31"
        malpedia_version = "20180911"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings: 
        $myagent = "myAgent" 
        $readfile = "read file error:" 
        $downfile = "down file success" 
        $avail = "Avaliable data:%u bytes" 
    condition: 
        3 of them
}
