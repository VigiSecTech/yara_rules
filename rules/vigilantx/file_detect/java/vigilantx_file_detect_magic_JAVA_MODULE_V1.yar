rule vigilantx_file_detect_magic_JAVA_MODULE_V1 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-15"
    severityLevel = "ARCHIVE"
    description   = "Detects  'Java module image (little endian), version 1.0' 'modules' files"

  strings:
    $header = { DA DA FE CA 00 00 01 }

  condition:
    $header at 0
}
