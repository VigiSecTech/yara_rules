rule vigilantx_file_detect_magic_RENPY_RPYC {
  meta:
    author        = "xCEVre"
    date          = "2025-04-04"
    severityLevel = "UNKNOWN"
    description   = "Detects '.rpyc' files"

  strings:
    $header = { 52 45 4E 50 59 20 52 50 43 32 01 00 00 00 2E 00 00 00 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_RENPY_RPYMC {
  meta:
    author        = "xCEVre"
    date          = "2025-04-05"
    severityLevel = "UNKNOWN"
    description   = "Detects '.rpymc' files(NO ZLIB)"

  strings:
    $header = { 52 45 4E 50 59 20 52 50 43 32 01 00 00 00 2E 00 00 00 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_RENPY_ARCHIVE {
  meta:
    author        = "xCEVre"
    date          = "2025-04-04"
    severityLevel = "ARCHIVE"
    description   = "Detects '.rpa' files"

  strings:
    $header = "RPA-3.0 00000000"

  condition:
    $header at 0
}
