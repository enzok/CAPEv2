rule NitrogenLoader
{
    meta:
        author = "enzok"
        description = "Nitrogen Loader"
        cape_type = "NitrogenLoader Loader"

    strings:
        $iv = {8B 84 24 [4] 8B 4C 24 ?? 0F AF C8 8B C1 [0-20] 89 44 24 ?? 48 8D 15 [3] 00}
        $aeskey = {48 8D 8C 24 [4] E8 [3] 00 48 8B C8 E8 [3] 00 4? 89 84 24 [4] 4? 8D 15 [3] 00}
        $decrypt1 = {48 89 54 24 ?? 4? 89 4C 24 ?? 4? 83 EC ?? C6 44 24 ?? 00 4? 8B 44 24 ?? 4? 8B 54 24 ?? B? 0E E8 [3] FF C6 44 24 ?? 0D}
        $decrypt2 = {EB ?? 0F B6 44 24 ?? FE C8 88 44 24 ?? 4? 8B 4C 24 ?? E8 [3] FF 4? 8B 4C 24 ?? E8 [3] FF 4? 8B 44 24 ?? 4? 8B 54 24 ?? 0F}
        $decrypt3 = {B6 4C 24 ?? E8 [3] FF 0F B6 44 24 ?? 85 C0 75 ?? EB ?? 4? 8B 4C 24 ?? E8 [3] FF EB ?? 33 C0 4? 83 C4 ?? C3}

    condition:
        $iv and $aeskey and 2 of ($decrypt*)
}

rule NitrogenLoader2
{
    meta:
        author = "enzok"
        description = "Nitrogen Loader"
        cape_type = "NitrogenLoader Loader"

    strings:
        $stringaes1 = {63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa}
        $stringaes2 = {52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b}
        $string1 = "BASS_GetEAXParameters"
        $string2 = "LoadResource"
        $syscallmakehashes = {48 89 4C 24 ?? 48 89 54 24 ?? 4? 89 44 24 ?? 4? 89 4C 24 ?? 4? 83 EC ?? B? [4] E8 [3] 00}
        $syscallnumber = {49 89 C3 B? [4] E8 [3] 00}
        $syscall = {48 83 C4 ?? 4? 8B 4C 24 ?? 4? 8B 54 24 ?? 4? 8B 44 24 ?? 4? 8B 4C 24 ?? 4? 89 CA 4? FF E3}

    condition:
        all of ($string*) or all of ($syscall*)
}