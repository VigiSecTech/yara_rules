rule vigilantx_file_detect_magic_JAVA_CLASS_v25 {
  meta:
    description = "Detects Java 25 (JDK 25) class file format"
    author      = "xCEVre"
    date        = "2025-07-05"

  strings:
    $magic = { CA FE BA BE 00 00 00 45 }

  condition:
    $magic at 0
}
