import "pe"

rule win_gold_dragon_w0 {
	meta:
        author = "Florian Roth"
        description = "Detects malware from Gold Dragon report"
        reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
        malpedia_version = "20180301"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	condition:
        pe.imphash() == "168c2f7752511dfd263a83d5d08a90db" or
        pe.imphash() == "0606858bdeb129de33a2b095d7806e74" or
        pe.imphash() == "51d992f5b9e01533eb1356323ed1cb0f" or
        pe.imphash() == "bb801224abd8562f9ee8fb261b75e32a"
}
