rule TrustConnect
{
    meta:
        description = "TrustConnect Payload"
        author = "enzok"
        cape_type = "TrustConnect Payload"
        hash = "51f62d2477d26446102aab3b9755532a54bc21cae24242bf51e275d701bf3c97"

    strings:
        $s1 = "TrustConnect" ascii wide
        $s2 = "ConnectAgent" ascii wide

        $log1 = "<deviceId>" ascii wide
        $log2 = "<installToken>" ascii wide
        $log3 = "<RunAgent>" ascii wide
        $log4 = "<agentVersion>" ascii wide

        $pdb = "/obj/Release/net8.0-windows/win-x64/" ascii wide

    condition:
        1 of ($s*) and
        2 of ($log*) and
        $pdb
}
