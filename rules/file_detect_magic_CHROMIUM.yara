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
