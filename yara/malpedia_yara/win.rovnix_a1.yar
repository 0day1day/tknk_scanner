rule win_rovnix_a1 {
    meta:
        author = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170628"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:AMBER"

    strings:
        $unpack     = { 55 8B EC  [0-2] (23|85) ??  83 EC 10  [0-2] (23|85) ??  8B 4D 08  [0-2] (23|85) ??  81 E1 FF 00 00 00  [0-2] (23|85) ??  83 44 0C 04 04 [0-2] (23|85) ??  8B E5 5D C2 04 00 }
        $BkInitialize_v11     = { B8 0D 00 00 C0  74 ??  8B 4? [1-2]  85 ??  74 ??  8B 4? 24 ??  50 52  FF D1         C2 10 00 }
        $BkInitialize_v12_15  = { FF D? [0-2] C2 10 00   8B 4? [1-2]  85 ??  74 ??                [0-3] FF D?  [0-2]  C2 10 00  B8 0D 00 00 C0  [0-2]  C2 10 00 }

   condition:
      any of them
}

