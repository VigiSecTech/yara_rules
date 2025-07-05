rule file_detect_magic_GNU_Message_Catalog{
    meta:
        author = "xCEVre"
        date = "2025-04-12"
        severityLevel= "INFORMATIONAL"
        description = "Detects 'GNU message catalog' '.mo' files"
    strings:
        $header = { DE 12 04 95 00 00 00 00 }
    condition:
        $header at 0
}
rule file_detect_magic_GNU_DB{
    meta:
        author = "xCEVre"
        date = "2025-04-12"
        severityLevel= "INFORMATIONAL"
        description = "Detects 'GNU dbm 1.x or ndbm database, little endian, 64-bit' '.mo' files"
    strings:
        $header = { CF 9A 57 13 00 10 00 00 00 10 00 00 00 00 00 00 00 10 00 00 09 00 00 00 00 10 00 00 ?? 00 00 00 }
    condition:
        $header at 0
}
