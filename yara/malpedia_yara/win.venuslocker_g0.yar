rule win_venuslocker_g0 {
	meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180106"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
	    
    strings: 
        $malware_name = "VenusLocker"
        $dotnet_elements_0 = "SetWallPaper"
        $dotnet_elements_1 = "PerfectMoneyLinkLabel"
        $dotnet_elements_2 = "BTCAddressTextBox3"


    condition:
       all of them
}
