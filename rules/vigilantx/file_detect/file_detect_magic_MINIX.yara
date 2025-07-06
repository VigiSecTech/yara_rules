rule vigilantx_file_detect_magic_MINIX_MODULE {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "INFORMATIONAL"
    description   = "Detects  '.minix' files"

  strings:
    $header = { 5F ?? ?? ?? ?? 2E 6D 69 6E 69 78 5F 6D 6F 64 75 6C 65 28 29 }  // _????.minix_module()

  condition:
    $header at 0
}
