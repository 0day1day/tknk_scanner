rule win_rombertik_w2 {
	meta:
		description = "Detects CarbonGrabber alias Rombertik Panel - file index.php"
		author = "Florian Roth"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		date = "2015-05-05"
		hash = "e6e9e4fc3772ff33bbeeda51f217e9149db60082"
        malpedia_version = "20170521"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
        
	strings:
		$s0 = "echo '<meta http-equiv=\"refresh\" content=\"0;url=index.php?a=login\">';" fullword ascii
		$s1 = "echo '<meta http-equiv=\"refresh\" content=\"2;url='.$website.'/index.php?a=login" ascii
		$s2 = "header(\"location: $website/index.php?a=login\");" fullword ascii
		$s3 = "$insertLogSQL -> execute(array(':id' => NULL, ':ip' => $ip, ':name' => $name, ':" ascii
		$s16 = "if($_POST['username'] == $username && $_POST['password'] == $password){" fullword ascii
		$s17 = "$SQL = $db -> prepare(\"TRUNCATE TABLE `logs`\");" fullword ascii
		
	condition:
		filesize < 46KB and all of them
}
