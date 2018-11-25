import "pe"
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-27
   Identifier: RGDoor
   Reference: https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
*/
rule win_rgdoor_w0 {
    meta:
        description = "Detects RGDoor backdoor used by OilRig group"
        author = "Florian Roth"
        reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/"
        date = "2018-01-27"
        score = 80
        hash1 = "a9c92b29ee05c1522715c7a2f9c543740b60e36373cb47b5620b1f3d8ad96bfa"
        malpedia_version = "20180208"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rgdoor"
    strings:
        $s1 = "MyNativeModule.dll" fullword ascii
        $s2 = "RGSESSIONID=" fullword ascii
        $s3 = "download$" fullword ascii
        $s4 = ".?AVCHelloWorld@@" fullword ascii
    condition:
        pe.imphash() == "47cb127aad6c7c9954058e61a2a6429a" or (2 of them)
}
