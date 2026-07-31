rule NitroBunnyDownloader
{
    meta:
        author = "enzok"
        description = "NitroBunnyDownloader"
        cape_type = "NitroBunnyDownloader Payload"
        hash = "960e59200ec0a4b5fb3b44e6da763f5fec4092997975140797d4eec491de411b"
    strings:
        $config1 = {41 B8 ?? ?? 00 00 48 8D 15 ?? ?? ?? 00 48 (89 | 8B) ??}
        $config2  = {48 8D 15 ?? ?? ?? 00 41 B8 ?? ?? 00 00 48 (89 | 8B) ??}
    condition:
        uint16(0) == 0x5A4D and 1 of ($config*)
}
