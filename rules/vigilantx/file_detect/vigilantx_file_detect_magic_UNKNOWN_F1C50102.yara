rule vigilantx_file_detect_magic_UNKNOWN_F1C50102 {
  meta:
    author        = "xCEVre"
    date          = "2025-07-06"
    severityLevel = "UNKNOWN"
  strings:
    $magic = { F1 C5 01 02 }

  condition:
    $magic at 0
}
