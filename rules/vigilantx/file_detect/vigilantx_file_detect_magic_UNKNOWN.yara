rule vigilantx_file_detect_magic_UNKNOWN_7B0A20202266 {
  meta:
    author        = "xCEVre"
    date          = "2025-07-06"
    severityLevel = "UNKNOWN"
  strings:
    $magic = { 7B 0A 20 20 22 66 }

  condition:
    $magic at 0
}
