rule win_neuron_w2 {
    meta:
        description = "Rule for detection of Neuron based on .NET function, variable and class names"
        author = "NCSC UK"
        hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
        source = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        malpedia_version = "20171123"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $class1 = "StorageUtils" ascii
        $class2 = "WebServer" ascii
        $class3 = "StorageFile" ascii
        $class4 = "StorageScript" ascii
        $class5 = "ServerConfig" ascii
        $class6 = "CommandScript" ascii
        $class7 = "MSExchangeService" ascii
    condition:
        all of them
}
