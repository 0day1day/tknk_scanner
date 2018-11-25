rule win_vmzeus_g1 {
    meta:
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        malpedia_version = "20170602"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
    strings:
        // push bot version, common in any encountered zeus-like bot.
        // push 2713h (BO_CLIENT_VERSION)
        $zeus_push_bot_version = { 68 13 27 00 00 }
        // this is also compiled like this in all binaries I have seen
        $decrypt_base_config = { 8b 45 b? 0f b6 00 8d 4d b? ff 14 85 ?? ?? ?? ?? 84 c0 75 }
        $sha1 = { 68 04 80 00 00 FF ?? ?? FF 15 }
        $resolve_api_hash = { 00 00 00 68 ?? ?? ?? ?? 8B CE A3}
        $vmzeus2000_0 = { 68 12 00 08 00 }
        $vmzeus2000_1 = { 68 14 00 08 00 }
        $vmzeus2000_2 = { 68 16 00 08 00 }

        
    condition:
        ($zeus_push_bot_version and $decrypt_base_config) and ($sha1 or #resolve_api_hash > 5 or (all of ($vmzeus2000_*)))
}
