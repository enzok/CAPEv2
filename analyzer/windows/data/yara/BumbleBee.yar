rule BumblebeeLoader
{
    meta:
        author = "enzo"
        description = "Bumblebee Loader"
        cape_options = "coverage-modules=gdiplus,ntdll-protect=0"
    strings:
        $str_set = {C7 ?? 53 65 74 50}
        $str_path = {C7 4? 04 61 74 68 00}
        $iternaljob = "IternalJob" 
    condition:
        all of them
}


rule Bumblebee
{
    meta:
        author = "enzo"
        description = "Bumblebee Anti-VM Bypass"
        cape_options = "bp0=$antivm-11,action0=jmp,count=0"
    strings:
        $antivm = {33 C9 E8 [3] 00 4? 8B C8 E8 [3] 00 4? 89 B5 [4] 4? 89 B5 [4] 4? C7 85 [4] 0F [3] 4? 89 B5 [4] C6 85 [4] 00}
    condition:
        any of them
}
