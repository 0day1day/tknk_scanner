rule win_adkoob_w0 {
    meta:
        author = "Felix Weyne, Sophos"
        malpedia_version = "20180606"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $facebook_cookie_firefox = "SELECT * FROM moz_cookies WHERE moz_cookies.host LIKE \"%.facebook.com\""  nocase ascii
        $facebook_cookie_chrome = "SELECT * FROM cookies WHERE cookies.host_key LIKE \"%.facebook.com\""  nocase ascii
        $facebook_regex_ad_account_id = "<td [^>]*?data-testid=\"all_accounts_table_account_id_cell\">([^<>]*?)</td>"  nocase wide
        $self_destruction = "/C ping localhost -n 4 > nul & del" nocase wide
    condition:
        all of them
}
