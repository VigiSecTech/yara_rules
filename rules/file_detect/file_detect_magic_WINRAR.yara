rule file_detect_magic_WINRAR {
    meta:
        author = "xCEVre"
        date = "2025-04-20"
        severityLevel = "ARCHIVE"
        description = "Detects winrar files"
    strings:
        $version_upto4 = { 52 61 72 21 1A 07 00 }
        $version_from5 = { 52 61 72 21 1A 07 01 00 }
    condition:
        any of them at 0
}
