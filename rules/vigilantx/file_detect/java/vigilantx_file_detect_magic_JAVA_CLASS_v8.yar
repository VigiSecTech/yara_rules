rule vigilantx_file_detect_magic_JAVA_CLASS_v8 {
  meta:
    description = "Detects Java 1.8 class file"
    author      = "xCEVre"
    date        = "2025-04-05"

  strings:
    $magic = { CA FE BA BE 00 00 00 34 }

  condition:
    $magic at 0
}
