rule vigilantx_file_detect_magic_VALVE_STEAM_CACHE_1 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-02"
    description   = "Обнаружение кеш файлов"
    severityLevel = "UNKNOWN"

  strings:
    $header = { 02 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 66 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_VALVE_STEAM_UNKNOWN_F {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects steam file regex 'f_[0-9]+'  "

  strings:
    $header = { 0C 00 00 00 42 50 4C 47 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_VALVE_STEAM_UNKNOWN_X_pbuf {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects steam file regex '[0-9]+_pbuf'"

  strings:
    $header_tiny = { 0A 32 0A 14 }
    $header_huge = { 0A 32 0A 14 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 12 14 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_VALVE_STEAM_Settings_manifest {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "INFORMATIONAL"
    description   = "Detects steam file with extension '.manifest'  "

  strings:
    $header = { D0 17 F6 71 ?? ?? ?? 00 0A }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_VALVE_STEAM_Settings_menu {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "INFORMATIONAL"
    description   = "Detects steam file with extension '.menu'  "

  strings:
    $header = "\"menubar\"\r\n{\r\n\t"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_VALVE_STEAM_AppState_acf {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "INFORMATIONAL"
    description   = "Detects steam file starts with \"AppState\" and extension '.acf'  "

  strings:
    $header = "\"AppState\"\n{\n\t\"appid\"\t\t\""

  condition:
    $header at 0
}
