rule vigilantx_file_detect_magic_Inno_Setup_idska32 {
  meta:
    author        = "xCEVre"
    date          = "2025-07-06"
    severityLevel = "UNKNOWN"

  strings:
    $magic = "idska32"

  condition:
    $magic at 0
}
