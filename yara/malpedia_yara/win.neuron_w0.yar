rule win_neuron_w0 {
    meta:
        description = "Rule for detection of Neuron based on commonly used strings"
        author = "NCSC UK"
        hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
        source = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        malpedia_version = "20171123"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $strServiceName = "MSExchangeService" ascii
        $strReqParameter_1 = "cadataKey" wide
        $strReqParameter_2 = "cid" wide
        $strReqParameter_3 = "cadata" wide
        $strReqParameter_4 = "cadataSig" wide
        $strEmbeddedKey = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnZ3WXRKcnNRZjVTcCtWVG9Rb2xuaEVkMHVwWDFrVElFTUNTNEFnRkRCclNmclpKS0owN3BYYjh2b2FxdUtseXF2RzBJcHV0YXhDMVRYazRoeFNrdEpzbHljU3RFaHBUc1l4OVBEcURabVVZVklVb        HlwSFN1K3ljWUJWVFdubTZmN0JTNW1pYnM0UWhMZElRbnl1ajFMQyt6TUhwZ0xmdEc2b1d5b0hyd1ZNaz08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+" wide
        $strDefaultKey = "8d963325-01b8-4671-8e82-d0904275ab06" wide
        $strIdentifier = "MSXEWS" wide
        $strListenEndpoint = "443/ews/exchange/" wide
        $strB64RegKeySubstring = "U09GVFdBUkVcTWljcm9zb2Z0XENyeXB0b2dyYXBo" wide
        $strName = "neuron_service" ascii
    condition:
        6 of ($str*)
}
