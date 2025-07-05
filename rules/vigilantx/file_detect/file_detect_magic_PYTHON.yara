rule file_detect_magic_SHEBANG_python {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "LOW"
    description   = "Detects 'Python script' files"

  strings:
    $header_1 = "#!/usr/bin/python"
    $header_2 = "#! /usr/bin/python"

  condition:
    any of them at 0
}

rule file_detect_magic_SHEBANG_ENV_python {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "LOW"
    description   = "Detects 'Python script' files"

  strings:
    $header_1 = "#! /usr/bin/env python"

  condition:
    any of them at 0
}

rule file_detect_magic_PYTHON_BYTE_COMPILED_CPython_3v8 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-05"
    severityLevel = "INFORMATIONAL"
    description   = "Detects '.pyc' files (Byte-compiled Python module for CPython 3.8)"

  strings:
    $header = "U\r\r\n"

  condition:
    $header at 0
}

rule file_detect_magic_PYTHON_BYTE_COMPILED_CPython_3v9 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-05"
    severityLevel = "INFORMATIONAL"
    description   = "Detects '.pyc' files (Byte-compiled Python module for CPython 3.9)"

  strings:
    $header = "a\r\r\n"

  condition:
    $header at 0
}

rule file_detect_magic_PYTHON_BYTE_COMPILED_2v7v {
  meta:
    author        = "xCEVre"
    date          = "2025-04-04"
    severityLevel = "INFORMATIONAL"
    description   = "Detects '.pyo' files (python 2.7 byte-compiled)"

  strings:
    $header = { 03 F3 0D 0A }

  condition:
    $header at 0
}
