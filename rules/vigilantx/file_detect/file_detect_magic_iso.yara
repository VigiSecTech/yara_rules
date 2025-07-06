rule vigilantx_file_detect_magic_iso_6_33ED90909090 {
  meta:
    author        = "xCEVre"
    date          = "2025-07-06"
    severityLevel = "ARCHIVE"

  strings:
    $magic = { 33 ED 90 90 90 90 }

  condition:
    $magic at 0
}
