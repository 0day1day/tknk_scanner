rule win_remcos_g0 {

    meta: 
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20180222"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        $string_remcos_inj = "Remcos_Mutex_Inj"
        $string_chrome_cookies = "Chrome Cookies found, cleared!"

    condition:
        all of them
}
