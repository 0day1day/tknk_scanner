/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule win_nettraveler_w2 {
	meta:
		description = "Export names for dll component"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
	
	strings:
		//dll component exports
		$d1 = "?InjectDll@@YAHPAUHWND__@@K@Z"
		$d2 = "?UnmapDll@@YAHXZ"
		$d3 = "?g_bSubclassed@@3HA"
		
	condition:
		any of them
}
