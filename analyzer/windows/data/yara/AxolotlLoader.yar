rule AxolotlLoader
{
    meta:
        author = "enzok"
        description = "AxolotlLoader Shellcode"
        cape_options = "clear,bp0=$decode*-2,action0=scan,hc0=1,bp1=$xor_loop*+2,action1=dumpimage,hc1=1,count=0"
        hash = "70a38d03a6c932de692912550730fb130db00f1708f756a9d1b5ac2e73da38cf"
    strings:
        $decode = {48 83 EF FF 48 8D 74 1E 01 80 3E 00 75 B7 49 8D 4D 10 49 8D 87 00 F0 0C 00 FF D0 C3}
        $xor_loop = {4? 8D 05 [4] 4? 8D 0D [4] 4? 81 30 [4] 4? 83 C0 04 4? 39 C8 72}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule AxolotlLoader2
{
    meta:
        author = "enzok"
        description = "AxolotlLoader Shellcode"
        cape_options = "clear,count=0,bp0=$alloc_size+14,action0=dumpsize:rdx,hc0=1,bp1=$decode*-2,action1=dump:eax,hc1=1"
        hash = "b4cac22658928377d866275ece28652b621f79a585dfe2c2e019f3a504cfc2a1"
    strings:
        $decode = {49 8D 4D 10 49 8D 87 [4] FF D0 C3}
        $alloc_size = {4? 83 EC ?? 4? 89 F9 4? C7 C2 [4] 4? C7 C0 40 00 00 00 4? 8D 4C 24 ?? 4? FF 97 [4] 4? 83 C4 ?? 85 C0 EB}
    condition:
        uint16(0) == 0x5A4D and any of them
}