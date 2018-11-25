rule win_darkcomet_a0 {
  meta:
    author = "David Cannings"
    description = "Strings from the Dark Comet 5.2 stub"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkcomet"
    malpedia_version = "20180123"
    malpedia_license = "CC BY-NC-SA 4.0"
    malpedia_sharing = "TLP:AMBER"
      
  // All strings from Dark Comet v5.2 "normal" sized stub
  strings:
    $str01 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!"
    $str02 = "ping 127.0.0.1 -n 4 > NUL"
    $str03 = "FILM003"
    $str04 = "FILM004"
    $str05 = "Ping|Respond [OK] for the ping !"
    $str06 = "BTRESULT"
    $str07 = "BTERROR"
    $str08 = "#BOT#URLDownload"
    $str09 = ") successfully dump in"
    $str10 = "ERR|Cannot listen to port, try another one..|"
    // Start of the RC4 decryption key
    $str11 = "#KCMDDC"
    
  condition:
    5 of them
}
