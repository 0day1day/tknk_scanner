rule win_sinowal_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20170605"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $123456789nke32 = "123456789nke32"
        $altavista_search_0 = "search?fr=altavista&itag=ody&q=%s%%2C%02x%02x%02x%02x%02x%02x%02x%02x%s&kgs=1&kls=0"
        $altavista_search_1 = "search?fr=altavista&itag=ody&q=%s%%2C%02x%02x%02x%02x%02x%02x%02x%02x%s&kgs=1&kls=0&p=%d"
        
    condition:
        all of them
}


