rule file_detect_magic_Chromium_ResourcePack_pak {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        description = "Обнаружение файла с ресурсами chromium ,имеет расширение .pak"
		severityLevel= "ARCHIVE"
    strings:
        $header = { 05 00 00 00 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? ?? 00 00 ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? 00 ?? ?? }
    condition:
        $header at 0
}


rule detect_chromium_v8cache {
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel = "UNKNOWN"
        description = "Detects V8 JavaScript engine cache files used by Chromium-based applications (e.g., Steam, Chromium) — typical for Code Cache/js and Shared Dictionary structures"
    strings:
        $ext_s = { 30 5C 72 A7 1B 6D FB FC 09 00 00 00 }
        $ext_0 = { 30 5C 72 A7 1B 6D FB FC 05 00 00 00 }
        $ext_any = { 30 5C 72 A7 1B 6D FB FC ?? 00 00 00 }
    condition:
        any of them at 0
}

