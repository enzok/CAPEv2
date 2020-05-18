rule CobaltStrikeBeacon34
{
    meta:
      author = "enzo"
      description = "Cobalt Strike Beacon Payload"
      cape_type = "CobaltStrikeBeacon Payload"
    strings:
      $ver3 = { 69 68 69 68 69 6b ?? ?? 69 }
      $ver4 = { 2e 2f 2e 2f 2e 2c ?? ?? 2e }
    condition: 1 of ($ver*)
}
