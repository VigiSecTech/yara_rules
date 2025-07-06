rule vigilantx_file_detect_magic_JAVA_MODULE {
  meta:
    author        = "xCEVre"
    date          = "2025-04-15"
    severityLevel = "ARCHIVE"
    description   = "Detects  'Java module image (little endian)' 'modules' files"

  strings:
    $header = { DA DA FE CA }

  condition:
    $header at 0
}
