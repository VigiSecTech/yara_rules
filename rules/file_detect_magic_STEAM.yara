rule file_detect_magic_VALVE_STEAM_CACHE_1 {
    meta:
        author = "xCEVre"
        date = "2025-04-02"
        description = "Обнаружение кеш файлов"
		severityLevel= "UNKNOWN"
    strings:
        $header = { 02 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 66 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 }
    condition:
        $header at 0
}

rule file_detect_magic_VALVE_STEAM_UNKNOWN_F{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "UNKNOWN"
        description = "Detects steam file regex 'f_[0-9]+'  "
    strings:
        $header = { 0C 00 00 00 42 50 4C 47 }
    condition:
        $header at 0
}
rule file_detect_magic_VALVE_STEAM_UNKNOWN_DATA_X{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "UNKNOWN"
        description = "Detects steam file regex 'data_[0-9]+'"
    strings:
        $header = { C3 CA 04 C1 00 00 02 00 }
    condition:
        $header at 0
}
rule file_detect_magic_VALVE_STEAM_UNKNOWN_X_pbuf{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "UNKNOWN"
        description = "Detects steam file regex '[0-9]+_pbuf'"
    strings:
        $header_tiny = { 0A 32 0A 14 }
        $header_huge = { 0A 32 0A 14 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 12 14 }
    condition:
        any of them at 0
}

rule file_detect_magic_VALVE_STEAM_Settings_manifest{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "INFORMATIONAL"
        description = "Detects steam file with extension '.manifest'  "
    strings:
        $header = { D0 17 F6 71 ?? ?? ?? 00 0A }
    condition:
        $header at 0
}
rule file_detect_magic_VALVE_STEAM_Settings_menu{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "INFORMATIONAL"
        description = "Detects steam file with extension '.menu'  "
    strings:
        $header = { 22 6D 65 6E 75 62 61 72 22 0D 0A 7B 0D 0A 09 }
    condition:
        $header at 0
}
rule file_detect_magic_VALVE_STEAM_AppState_acf{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "INFORMATIONAL"
        description = "Detects steam file starts with \"AppState\" and extension '.acf'  "
    strings:
        $header = { 22 41 70 70 53 74 61 74 65 22 0A 7B 0A 09 22 61 70 70 69 64 22 09 09 22 }
    condition:
        $header at 0
}
