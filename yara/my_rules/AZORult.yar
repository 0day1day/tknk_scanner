rule AZORult {
    strings:
        $s0 = "PasswordsList.txt"
        $constant1 = {85 C0 74 40 85 D2 74 31 53 56 57 89 C6 89 D7 8B 4F FC 57} // Azorult grabs .txt and .dat files from Desktop

    condition:
        all of them
}
