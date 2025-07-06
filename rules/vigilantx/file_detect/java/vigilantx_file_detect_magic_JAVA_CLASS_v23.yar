rule vigilantx_file_detect_magic_JAVA_CLASS_v23 {
  meta:
    description = "Detects Java 23 class file"
    author      = "xCEVre"
    date        = "2025-04-05"

  strings:
    $magic = { CA FE BA BE 00 00 00 43 }

  condition:
    $magic at 0
}
