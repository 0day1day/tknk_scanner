rule win_neuron_w1 {
    meta:
        description = "Rule for detection of Neuron based on a standalone signature from .NET metadata"
        author = "NCSC UK"
        hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
        source = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        malpedia_version = "20171123"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $a = {eb073d151231011234080e12818d1d051281311d1281211d1281211d128121081d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281}
        $dotnetMagic = "BSJB" ascii
    condition:
        all of them
}
