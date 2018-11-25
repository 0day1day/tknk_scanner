rule win_sendsafe_g0 {
    meta:
        author="mak"
        malpedia_version = "20170413"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        /* report urls */
        $url0 = "/SuccessMails?CampaignNum=%ld" fullword
        $url1 = "/TimedOutMails?CampaignNum=%ld" fullword
        $url2= "/InvalidMails?CampaignNum=%ld" fullword

        /* debug strings */
        $d0 = "Failed to download settings: InternetConnect failed (%d)" fullword
        $d1 = "Failed to download settings: HttpOpenRequest failed (%d)" fullword
        $d2 = "Failed to download settings: HttpSendRequest failed (%d)" fullword
        $d3 = "Failed to download settings: InternetReadFile failed (%d)" fullword

        $xor_key = "UNREGISTERED" fullword
        $user_agent = "Mozilla" fullword

        /* get config */
        $get_config = {0F 8e [4] C6 45 E0 ?? C6 45 E1 ?? C6 45 E2 ?? C6 45 E3 ?? C6 45 E4 ?? C6 45 E5}
        
    condition:
        all of them
}
