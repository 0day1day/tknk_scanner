rule win_ratabankapos_w1 {
    meta:
        author = "Threat Exchange http://blog.trex.re.kr/3"
        malpedia_version = "20180613"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $cardinfo_parsing = {6A 25 83 ?? F0}
        $subs_table = { 5A 43 4B 4F [6] 41 44 42 4C [7] 4E 58 [6] 59}
    condition:
        all of them
}
