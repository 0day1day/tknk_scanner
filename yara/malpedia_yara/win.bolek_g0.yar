rule win_bolek_g0 {
    meta:
        author= "mak"
        module= "kbot"
        malpedia_version = "20170519"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        
    strings:
        $bot_cfg = "BASECONFIG......FJ"
        $injini = "INJECTS.INI"
        $kbotini = "KBOT.INI"
        $bot0 = "BotConfig"
        $bot1 = "BotCommunity"
        $push_version = { 5? 68 [4] 68 [4] 5? E8 [4] 83 C4 10 85 C0 0F}
    condition: 
        all of them
}
