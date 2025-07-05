rule file_detect_magic_SHEBANG_python{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "LOW"
        description = "Detects 'Python script' files"
    strings:
        $header_1 = { 23 21 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E } 	// '#!/usr/bin/python'
        $header_2 = { 23 21 20 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E } // '#! /usr/bin/python'
    condition:
        any of them at 0
}
rule file_detect_magic_SHEBANG_ENV_python{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "LOW"
        description = "Detects 'Python script' files"
    strings:
        $header_1 = { 23 21 20 2F 75 73 72 2F 62 69 6E 2F 65 6E 76 20 70 79 74 68 6F 6E } 	// '#! /usr/bin/env python'
    condition:
        any of them at 0
}
rule file_detect_magic_PYTHON_BYTE_COMPILED_CPython_3v8{
    meta:
        author = "xCEVre"
        date = "2025-04-05"
        severityLevel= "INFORMATIONAL"
        description = "Detects '.pyc' files (Byte-compiled Python module for CPython 3.8)"
    strings:
        $header = { 55 0D 0D 0A  }
    condition:
        $header at 0
}

rule file_detect_magic_PYTHON_BYTE_COMPILED_CPython_3v9{
    meta:
        author = "xCEVre"
        date = "2025-04-05"
        severityLevel= "INFORMATIONAL"
        description = "Detects '.pyc' files (Byte-compiled Python module for CPython 3.9)"
    strings:
        $header = { 61 0D 0D 0A  }
    condition:
        $header at 0
}
rule file_detect_magic_PYTHON_BYTE_COMPILED_2v7v{
    meta:
        author = "xCEVre"
        date = "2025-04-04"
        severityLevel= "INFORMATIONAL"
        description = "Detects '.pyo' files (python 2.7 byte-compiled)"
    strings:
        $header = { 03 F3 0D 0A }
    condition:
        $header at 0
}
