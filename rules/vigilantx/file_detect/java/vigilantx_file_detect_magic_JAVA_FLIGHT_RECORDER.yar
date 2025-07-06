rule vigilantx_file_detect_magic_JAVA_FLIGHT_RECORDER {
  meta:
    author = "xCEVre"
    date   = "2025-04-05"

  strings:
    $magic = { 46 4C 52 00 00 02 00 01 00 00 }

  condition:
    $magic at 0
}
