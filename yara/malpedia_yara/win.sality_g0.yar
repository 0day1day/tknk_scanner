rule win_sality_g0 {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de"
		description = "2013-11-11 Sality Infector"
        malpedia_version = "20170511"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings: 
        $kuku = "kukutrust"            // included since years
        $driver = "amsint32"             // driver name
        $mutex = "purity_control"       // mutex and probably an X-Files reference :)
        $poly = "Simple Poly Engine"   // Polymorphic engine just for infecting files
        
        
    condition:
        (3 of ($kuku, $driver, $mutex, $poly))
}
