rule Free_VPN_Lumma_Dropper_Detection {
  meta:
    description = "Detects Lumma Stealer dropper disguised as VPN or Minecraft tool based on domains, and hashes"
    author      = "Cyfirma Research"
    date        = "2025-07-08"
    mal_type    = "Stealer"

  strings:
    // Malicious files
    $sha256_launcher = "acbaa6041286f9e3c815cd1712771a490530f52c90ce64da20f28cfa0955a5ca"
    $sha256_dll      = "15b644b42edce646e8ba69a677edcb09ec752e6e7920fd982979c714aece3925"
    // Known C2 domains
    $dom1            = "explorationmsn.store"
    $dom2            = "snailyeductyi.sbs"
    $dom3            = "ferrycheatyk.sbs"
    $dom4            = "deepymouthi.sbs"
    $dom5            = "wrigglesight.sbs"
    $dom6            = "captaitwik.sbs"
    $dom7            = "sidercotay.sbs"
    $dom8            = "heroicmint.sbs"
    $dom9            = "monstourtu.sbs"

  condition:
    any of ($dom*) or $sha256_launcher or $sha256_dll
}
