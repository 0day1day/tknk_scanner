rule AZORult {
    strings:
        $s0 = "PasswordsList.txt"
        $s1 = "CookieList.txt"
        $s2 = "getcfg"

    condition:
        all of them
}
