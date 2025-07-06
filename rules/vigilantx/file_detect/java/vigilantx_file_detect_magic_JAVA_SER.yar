rule vigilantx_file_detect_magic_JAVA_SER {
  meta:
    description = "Detects Java serialized object files of any version at the beginning of the file"
    author      = "xCEVre"
    date        = "2025-04-01"

  strings:
    $version_5 = { AC ED 00 05 }  // Версия 5

  condition:
    any of them at 0
}
