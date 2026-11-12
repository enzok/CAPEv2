import "math"

rule AxolotLoader
{
    meta:
        author = "enzok"
        description = "AxolotLoader Payload"
        cape_type = "AxolotLoader Payload"
    strings:
        $s_api_init_guid = /\/api\/init\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/ ascii nocase
        $s_inline_post = {E8 05 00 00 00 50 4F 53 54 00}
        $s_jfif_stub = {FF D8 FF E0 00 10 4A 46 49 46 00}
        $win1 = "InternetOpenA" ascii
        $win2 = "InternetConnectA" ascii
        $win3 = "HttpOpenRequestA" ascii
        $win4 = "HttpSendRequestA" ascii
        $win5 = "InternetReadFile" ascii
        $win6 = "InternetCloseHandle" ascii
        $http_hdr = "Content-Type: image/jpeg" ascii wide
        $http_ua  = /Mozilla\/5\.0 \(Windows NT [0-9\.]+; Win64; x64; rv:[0-9\.]+\) Gecko\/20100101 Firefox\/[0-9\.]+/ ascii wide
        $wh1 = "WinHttpOpen" ascii
        $wh2 = "WinHttpConnect" ascii
        $wh3 = "WinHttpOpenRequest" ascii
        $wh4 = "WinHttpAddRequestHeaders" ascii
        $wh5 = "WinHttpSendRequest" ascii
        $wh6 = "WinHttpReceiveResponse" ascii
        $wh7 = "WinHttpQueryDataAvailable" ascii
    condition:
        2 of ($s_*) and 1 of ($http*) and (4 of ($win*) or 4 of ($wh*))
}

rule AxolotLoaderDll
{
    meta:
        author = "enzok"
        description = "AxolotLoaderDll Payload"
        cape_type = "AxolotLoader Payload"
strings:
        $resolver_loadlibrary = {E8 0D 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 [1-16] 41 FF (97 [3] 00 | D6)}
        $call_decoded_buffer = {(49 8D 4D 10 | 4C 89 F9) [0-16] 49 8D 87 [3] 00 [0-30] FF (D0 | E0)}
        $alloc = {4? 83 EC ?? [2-12] 4? C7 ?? [4] 4? C7 C0 40 00 00 00 4? 8D ?? 24}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule AxolotLoaderShellCode
{
    meta:
        author = "enzok"
        description = "AxolotLoaderShellCode Payload"
        cape_type = "AxolotLoader Payload"
    strings:
        $start = {C0 0F 84 [4] [0-6] FF D8 FF E0 00 10 4A 46 49 46}
        $xor_loop = {4? 83 E4 ?? 4? 83 EC ?? 4? 8D 05 [4] 4? 8D 0D [4] [7-13] 4? 83 C0 0? 4? 39 C8 72}
        $decoded1 = {48 39 F6 48 0F 44 31 48 39 FF 48 0F 44 79 08 E8}
        $decoded2 = {48 39 F6 75 ?? 48 39 F6 75 ?? 48 8B 31 48 39 FF 48 0F 44 79 08 E8}
    condition:
        $start and $xor_loop and 1 of ($decoded*)
}

rule AxolotLoaderXorStub
{
    meta:
        author = "enzok"
        description = "AxolotLoaderXorStub Payload"
        cape_type = "AxolotLoader Payload"
    strings:
        $stub = {49 BF [8] 48 BB [8] 48 83 E4 F0 48 8D 05 [4] 48 8D 15 [4] 48 B9 [8] 48 31 08 48 83 C0 08 48 39 D0 72 F4}
    condition:
        $stub
}

rule AxolotLoaderWordlist
{
    meta:
        author = "enzok"
        description = "AxolotLoader wordlist-encoded stage 2"
        cape_type = "AxolotLoader Payload"
    condition:
        filesize > 16KB and filesize < 4MB and uint16(0) != 0x5A4D
        and math.count(0x00, 0, 2048) >= 120 and math.count(0x00, 0, 2048) <= 512
        and for all i in (0..2047) : (
            uint8(i) == 0x00 or (uint8(i) >= 0x30 and uint8(i) <= 0x39) or
            (uint8(i) >= 0x41 and uint8(i) <= 0x5A) or (uint8(i) >= 0x61 and uint8(i) <= 0x7A)
        )
        and for all i in (0..1022) : (uint16(i) != 0x0000)
}

rule AxolotLoaderSideloadDll
{
    meta:
        author = "enzok"
        description = "AxolotLoader trojanized dll"
        cape_type = "AxolotLoader Loader"
    strings:
        // L"kernel32.dll" "VirtualAlloc" L"msvcrt.dll" "wcsrchr" "SetCurrentDirectoryW" (the wordlist file name follows)
        $pool = { 6B 00 65 00 72 00 6E 00 65 00 6C 00 33 00 32 00 2E 00 64 00 6C 00 6C 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 6D 00 73 00 76 00 63 00 72 00 74 00 2E 00 64 00 6C 00 6C 00 00 00 77 63 73 72 63 68 72 00 53 65 74 43 75 72 72 65 6E 74 44 69 72 65 63 74 6F 72 79 57 00 }
        $c_getpc   = { 48 83 E4 F0 E8 00 00 00 00 [0-140] 49 81 EF }
        $c_wcsrchr = { BA 5C 00 00 00 FF D0 48 85 C0 (74 ?? | 0F 84 ?? ?? ?? ??) [0-140] 66 C7 40 02 00 00 }
        $c_open    = { BA 00 00 00 80 [0-140] 48 C7 44 24 20 03 00 00 00 }
        $c_tail    = { 4C 89 7F 02 [0-140] 4C 89 6F 0C [0-140] FF E7 }
    condition:
        uint16(0) == 0x5A4D and ($pool or 3 of ($c_*))
}
