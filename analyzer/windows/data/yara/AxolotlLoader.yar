rule AxolotlLoader
{
    meta:
        author = "enzok"
        description = "AxolotlLoader Shellcode"
        cape_options = "clear,count=0,bp0=$xor_loop*+2,action0=dumpimage,hc0=1,bp1=$decode*-2,action1=scan,hc1=1"
        hash = "70a38d03a6c932de692912550730fb130db00f1708f756a9d1b5ac2e73da38cf"
    strings:
        $decode = {49 8D 4D 10 49 8D 87 [4] FF D0 C3}
        $xor_loop = {4? 8D 05 [4] 4? 8D 0D [4] 4? 81 30 [4] 4? 83 C0 04 4? 39 C8 72}
    condition:
        all of them
}