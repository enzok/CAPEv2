rule CobaltStrikeBeacon34
{
    meta:
      author = "enzo"
      description = "Cobalt Strike Beacon ver 3/4 Payload"
      cape_type = "CobaltStrikeBeacon34 Payload"
    strings:
      $ver3 = { 69 68 69 68 69 6b }
      $ver4 = { 2e 2f 2e 2f 2e 2c }
    condition: 1 of ($ver*)
}
