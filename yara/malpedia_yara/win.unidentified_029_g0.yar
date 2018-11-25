rule win_unidentified_029_g0 {

    meta: 
        author = "pnx"
        info = "created with malpedia YARA rule editor"
        malpedia_version = "20170705"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"

    strings:
        // potentially related to staging of its actual code
        $dotnet_parsing = "[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String([System.IO.File]::ReadAllText" wide
        $dotnet_invocation = "EntryPoint.Invoke($null,$null)" wide
        $comment = "Sweet home assembly" wide ascii

    condition:
        all of them
}
