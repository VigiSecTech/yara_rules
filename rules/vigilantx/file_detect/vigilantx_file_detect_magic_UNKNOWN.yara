rule vigilantx_file_detect_magic_UNKNOWN_7B0A20202266 {
  meta:
    author        = "xCEVre"
    date          = "2025-07-06"
    severityLevel = "UNKNOWN"
  strings:
    $magic = "{\n  \"f"

  condition:
    $magic at 0
}


rule vigilantx_file_detect_magic_UNKNOWN_5B4348415054 {
  meta:
    author        = "xCEVre"
    date          = "2025-07-06"
    severityLevel = "UNKNOWN"
  strings:
    $magic = "[CHAPT"

  condition:
    $magic at 0
}


rule vigilantx_file_detect_magic_UNKNOWN_232074686973 {
  meta:
    author        = "xCEVre"
    date          = "2025-07-06"
    severityLevel = "UNKNOWN"
  strings:
    $magic = "# this is for "

  condition:
    $magic at 0
}



rule vigilantx_file_detect_magic_UNKNOWN_230A2320436F {
  meta:
    author        = "xCEVre"
    date          = "2025-07-06"
    severityLevel = "UNKNOWN"
  strings:
    $magic = "#\n# Configuration for "
  condition:
    $magic at 0
}


rule vigilantx_file_detect_magic_UNKNOWN_23205761636F {
  meta:
    author        = "xCEVre"
    date          = "2025-07-06"
    severityLevel = "UNKNOWN"
  strings:
    $magic = "# Wacom\n# "
  condition:
    $magic at 0
}
