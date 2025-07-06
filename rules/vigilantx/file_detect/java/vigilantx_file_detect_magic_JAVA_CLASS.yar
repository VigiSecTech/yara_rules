rule vigilantx_file_detect_magic_JAVA_CLASS {
  meta:
    description = "Detects Java class file"
    author      = "xCEVre"
    date        = "2025-04-05"

  strings:
    $magic = { CA FE BA BE 00 00 00 }

  condition:
    $magic at 0
}
