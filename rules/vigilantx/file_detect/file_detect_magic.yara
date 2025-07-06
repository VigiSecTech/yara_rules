// enum severityLevel:
//	INFORMATIONAL, // Просто информация, нет угрозы
//	LOW,           // Минимальный риск
//	MEDIUM,        // Средний уровень риска
//	HIGH,          // Значительный риск
//	CRITICAL       // Критическая угроза
//
//	ARCHIVE       // Используется для хранилищ (архивы и тд)
//	UNKNOWN       // Не известно

rule vigilantx_file_detect_magic_Bethesda_ESM {
  meta:
    author        = "xCEVre"
    date          = "2025-04-26"
    severityLevel = "UNKNOWN"
    description   = "Bethesda ESM: (Elder Scrolls Master file) , Используется в сериях игр The Elder Scrolls, Fallout"

  strings:
    $magic_tiny = "TES4"
    $magic_full = { 54 45 53 34 ?? ?? 00 00 81 00 00 00 00 00 00 00 00 00 00 00 83 00 00 00 48 45 44 52 0C 00 ?? ?? }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_ba2 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-26"
    severityLevel = "UNKNOWN"
    description   = "files with '.ba2' extension"

  strings:
    $magic_tiny = "BTDX"
    $magic_32   = { 42 54 44 58 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_csg {
  meta:
    author        = "xCEVre"
    date          = "2025-04-26"
    severityLevel = "UNKNOWN"
    description   = "files with '.csg' extension"

  strings:
    $magic_tiny = "bcsg"
    $magic_32   = { 62 63 73 67 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_cdx {
  meta:
    author        = "xCEVre"
    date          = "2025-04-26"
    severityLevel = "UNKNOWN"
    description   = "files with '.cdx' extension"

  strings:
    $magic_tiny = "bcdx"
    $magic_32   = { 62 63 64 78 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_video_Bink {
  meta:
    author        = "xCEVre"
    date          = "2025-04-26"
    severityLevel = "INFORMATIONAL"
    description   = "Bink Video 2 rev.g"

  strings:
    $magic = "KB2g"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_archive_FreeArc {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "ARCHIVE"
    description   = "Detects 'FreeArc archive <http://freearc.org>' files"

  strings:
    $magic_tiny = { 41 72 43 01 }
    $magic_huge = { 41 72 43 01 00 00 06 07 41 72 43 01 02 73 74 6F 72 69 6E 67 00 10 10 11 55 33 BC 10 12 71 82 44 48 28 EE 1F }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_SHEBANG_PERL {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "LOW"
    description   = "Detects 'Perl script text executable"

  strings:
    $header_1 = "#!/usr/bin/perl"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_SHEBANG_SH {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "LOW"
    description   = "Detects 'POSIX shell script' files"

  strings:
    $header_1 = "#!/bin/sh"
    $header_2 = "#! /bin/sh"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_SHEBANG_ENV_BASH {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "LOW"
    description   = "Detects 'Bourne-Again shell script' files"

  strings:
    $header = "#!/usr/bin/env bash"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_SVG {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "INFORMATIONAL"
    description   = "Detects 'SVG Scalable Vector Graphics image' files"

  strings:
    $header = { 3C 73 76 67 20 ?? ?? ?? ?? ?? }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_xpm {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "INFORMATIONAL"
    description   = "Detects 'X pixmap image text' '.xpm' files"

  strings:
    $header = "/* XPM */\nstatic char * "

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_CRYPTO_PEM_RSA_PRIVATE_KEY {
  meta:
    author        = "xCEVre"
    date          = "2025-04-05"
    severityLevel = "INFORMATIONAL"
    description   = "Detects (PEM RSA private key) files"

  strings:
    $header = "-----BEGIN RSA PRIVATE KEY-----"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_CRYPTO_PEM_CERTIFICATE {
  meta:
    author        = "xCEVre"
    date          = "2025-04-05"
    severityLevel = "INFORMATIONAL"
    description   = "Detects PEM certificate files"

  strings:
    $start = "-----BEGIN CERTIFICATE-----"
    $end   = "-----END CERTIFICATE-----"

  condition:
    any of them
}

rule vigilantx_file_detect_magic_CRYPTO_DH_PARAMETERS {
  meta:
    author        = "xCEVre"
    date          = "2025-04-05"
    severityLevel = "INFORMATIONAL"
    description   = "Detects files with DH PARAMETERS"

  strings:
    $start = "-----BEGIN DH PARAMETERS-----"
    $end   = "-----END DH PARAMETERS-----"

  condition:
    any of them
}

rule vigilantx_file_detect_magic_ELF {
  meta:
    author        = "xCEVre"
    date          = "2025-04-05"
    severityLevel = "UNKNOWN"
    description   = "Detects ELF files"

  strings:
    $header = "\x7fELF"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_SpaceRangersHD_Save {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "INFORMATIONAL"
    description   = "Detects '.sav' files"

  strings:
    $header = { 52 00 53 00 47 00 00 00 76 00 31 00 36 00 37 00 00 00 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_Composite_Document_File_V2 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "UNKNOWN"
    description   = "Detects 'Composite Document File V2 Document' '.s14' files"

  strings:
    $magic = { D0 CF 11 E0 A1 B1 1A E1 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_PaintShop_Pro_color_palette {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "UNKNOWN"
    description   = "Detects 'PaintShop Pro color palette' '.pal' files"

  strings:
    $magic = "JASC-PAL\r\n0100\r\n256\r\n"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_Targa {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "INFORMATIONAL"
    description   = "Detects 'Targa image data' '.tga' files"

  strings:
    $magic_1 = { 00 00 02 00 00 00 00 00 00 00 00 00 }
    $magic_2 = { 00 00 0A 00 00 00 00 00 00 00 00 00 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_tab {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "UNKNOWN"
    description   = "Detects '.tab' files"

  strings:
    $magic = "Dummy\t0\tEmpty\r\nID"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_NVIDIA_GLCache {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "UNKNOWN"
    description   = "Detects '.toc' '.bin' files"

  strings:
    $magic_any = { 43 44 56 4E 00 00 ?? 00 }
    $magic_3   = { 43 44 56 4E 00 00 03 00 }
    $magic_4   = { 43 44 56 4E 00 00 04 00 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_mhr {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "UNKNOWN"
    description   = "Detects '.mhr' files"

  strings:
    $magic = "MinPHR02"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_slp {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "UNKNOWN"
    description   = "Detects '.slp' files"

  strings:
    $magic = "2.0N"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_ted {
  meta:
    author        = "xCEVre"
    date          = "2025-04-12"
    severityLevel = "UNKNOWN"
    description   = "Detects '.ted' files"

  strings:
    $magic = { 00 00 00 00 ?? 00 00 00 00 04 01 02 00 00 01 04 ?? 00 00 00 02 04 ?? 00 00 00 03 04 ?? 00 00 00 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_mm {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects '.mm' files"

  strings:
    $magic = { 49 44 20 20 ?? ?? ?? ?? ?? 20 ?? ?? 20 20 20 ?? ?? 20 20 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_DRS {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects '.DRS' files"

  strings:
    $magic = { 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 32 30 30 31 20 4C 75 63 61 73 41 72 74 73 20 45 6E 74 65 72 74 61 69 6E 6D 65 6E 74 20 43 6F 6D 70 61 6E 79 20 4C 4C 43 1A 00 00 00 00 00 31 2E 30 30 73 77 62 67 00 00 00 00 00 00 00 00 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_CPX {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects '.CPX' files"

  strings:
    $magic = "1.00XCAM"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_cp1 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects '.cp1' files"

  strings:
    $magic = "1.001CAM"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_APPLE_DESKTOP_SERVICES_STORE {
  meta:
    author        = "xCEVre"
    date          = "2025-04-04"
    severityLevel = "INFORMATIONAL"
    description   = "Detects '.DS_Store' files"

  strings:
    $header = { 00 00 00 01 42 75 64 31 00 00 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_UNITY_LEVEL {
  meta:
    author        = "xCEVre"
    date          = "2025-04-04"
    severityLevel = "INFORMATIONAL"
    description   = "Detects levelX files"

  strings:
    $header = { 00 00 00 00 00 00 00 00 00 00 00 16 00 00 00 00 00 00 00 00 00 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_UNITY_resource {
  meta:
    author        = "xCEVre"
    date          = "2025-04-04"
    severityLevel = "INFORMATIONAL"
    description   = "Detects '.resource' files"

  strings:
    $header = { 46 53 42 35 01 00 00 00 01 00 00 00 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_WINE_REG_V2 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "INFORMATIONAL"
    description   = "Detects wine registry file with extension '.reg'"

  strings:
    $header = "WINE REGISTRY Version 2"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_MS_Windows_Icon_Resource {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "INFORMATIONAL"
    description   = "Detects 'MS Windows icon resource' files extension '.ico'"

  strings:
    $header_1 = { 00 00 01 00 ?? 00 ?? ?? ?? 00 01 00 ?? }
    $header_2 = { 00 00 01 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_MS_Window_Setup_INFormation {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "INFORMATIONAL"
    description   = "Detects 'Windows setup INFormation' files extension '.inf'"

  strings:
    $header_0 = "[Version]\nSignature=\"$CHICAGO$\""
    $header_1 = "[Version]\nSignature=\"$CHICAGO$\"\nClassGuid={"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_1_dat {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects UNKNOWN files extension '.dat'"

  strings:
    $header_1 = { 53 54 52 47 01 00 00 00 5A }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_2_dat {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects UNKNOWN files extension '.dat'"

  strings:
    $header_1 = { 44 00 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? 00 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_1_bin {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects UNKNOWN files extension '.bin'"

  strings:
    $header_1 = { 00 63 61 63 68 65 00 02 63 72 63 00 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_foz {
  meta:
    author        = "xCEVre"
    date          = "2025-04-11"
    severityLevel = "UNKNOWN"
    description   = "Detects UNKNOWN files extension '.foz'"

  strings:
    $header_1 = { 81 46 4F 53 53 49 4C 49 5A 45 44 42 00 00 00 06 }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_CHROMIUM_LOCALE_PACK {
  meta:
    author        = "xCEVre"
    date          = "2025-04-03"
    severityLevel = "UNKNOWN"
    description   = "Detectsfiles with extension '.pak' "

  strings:
    $header = { 05 00 00 00 01 00 00 00 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_RVDATA2 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-03"
    severityLevel = "INFORMATIONAL"
    description   = "Detects rvdata2 files"

  strings:
    $header = { 04 08 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_RIFF {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"
    description   = "Detects RIFF files"
    reference_0   = "https://en.wikipedia.org/wiki/Resource_Interchange_File_Format"

  strings:
    $riff_header = { 52 49 46 46 ?? ?? ?? ?? }  // "RIFF"+size

  condition:
    $riff_header at 0
}

rule vigilantx_file_detect_magic_RIFF_AVI {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"
    description   = "Detects RIFF AVI files"

  strings:
    $avi = { 41 56 49 20 4C 49 53 54 ?? ?? ?? ?? }

  condition:
	vigilantx_file_detect_magic_RIFF and $avi at 8
}

rule vigilantx_file_detect_magic_RIFF_WAV {
  meta:
    description   = "Detects RIFF WAV (Wave Audio File Format) files"
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $wave_marker = "WAVE"

  condition:
    vigilantx_file_detect_magic_RIFF and $wave_marker at 8
}

rule vigilantx_file_detect_magic_RIFF_WEBP {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"
    reference_0   = "https://en.wikipedia.org/wiki/WebP"
    description   = "Detects WebP image files by their magic bytes"

  strings:
    $webp_header = "WEBP"

  condition:
    vigilantx_file_detect_magic_RIFF and $webp_header at 8
}

rule vigilantx_file_detect_magic_CEPACK {
  meta:
    author        = "xCEVre"
    date          = "2025-04-02"
    description   = "Обнаружение файлов CEPACK"
    severityLevel = "UNKNOWN"

  strings:
    $header = "CEPACK"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_EXT_PKG_1 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-02"
    description   = "Обнаружение не известного типа с расширением .pkg"
    severityLevel = "UNKNOWN"

  strings:
    $header = { 04 00 00 00 AA 00 00 00 01 00 00 00 9E 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_IMAGE_CONTAINER_1 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    description   = "Обнаружение контейнера неизвестного типа(FIXME НАЙТИ И ДОПОЛНИТЬ) с изображениями"
    severityLevel = "ARCHIVE"

  strings:
    $header_1 = { 00 00 00 00 01 00 ?? ?? ?? 00 }
    $header_2 = { 00 00 00 00 01 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 01 ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? }

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_UNKNOWN_ADS_DATA_kva {
  meta:
    author      = "xCEVre"
    date        = "2025-04-01"
    description = "Обнаружение файлов рекламного SDK не известной мне компании, файлы обычно имеют .kva расширение"

  strings:
    $header = { ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 06 ?? ?? ?? }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_grafana_BeylaConfig {
  meta:
    author = "xCEVre"
    date   = "2025-04-01"

  strings:
    $magic = "#beyla_ids\n"

  condition:
    $magic at 0
}

rule vigilantx_file_detect_magic_XML {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $xml_BOM    = { EF BB BF }
    $xml_header = "<?xml"

  condition:
    ($xml_BOM at 0 and $xml_header at 3) or ($xml_header at 0)
}

rule vigilantx_file_detect_magic_HTML {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $tab_html_tag = { ?? 3C 68 74 6D 6C 3E }
    $doctype      = "<!DOCTYPE" nocase wide ascii
    $html_tag     = "<html" nocase wide ascii

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_AllInOneOfflineMaps {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    description   = "Detect generic binary navigation format containing coordinate data and application metadata"
    severityLevel = "INFORMATIONAL"

  strings:
    $header = { 50 50 ?? 01 00 00 ?? ?? ?? ?? ?? ?? 00 00 00 ?? }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_AllInOneOfflineMaps_WPT {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $header = "\n"  // третий байт сигнализирующий что файл должен иметь формат ".wpt"

  condition:
    vigilantx_file_detect_magic_AllInOneOfflineMaps and $header at 2
}

rule vigilantx_file_detect_magic_AllInOneOfflineMaps_ARE {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $header = "\r"  // третий байт сигнализирующий что файл должен иметь формат ".are"

  condition:
    vigilantx_file_detect_magic_AllInOneOfflineMaps and $header at 2
}

rule vigilantx_file_detect_magic_AllInOneOfflineMaps_RTE {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $header = { 0C }  // третий байт сигнализирующий что файл должен иметь формат ".are"

  condition:
    vigilantx_file_detect_magic_AllInOneOfflineMaps and $header at 2
}

rule vigilantx_file_detect_magic_AllInOneOfflineMaps_TRK {
  meta:
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $header = { 0e }  // третий байт сигнализирующий что файл должен иметь формат ".are"

  condition:
    vigilantx_file_detect_magic_AllInOneOfflineMaps and $header at 2
}

rule vigilantx_file_detect_magic_SQLITE3 {
  meta:
    description   = "Detects SQLite version 3 database files"
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $magic_header = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 }  // "SQLite format 3\0"

  condition:
    $magic_header at 0
}

rule vigilantx_file_detect_magic_SQLITE3_SHM {
  meta:
    description   = "Detects SQLite Write-Ahead Log shared memory (.db-shm) files"
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    // 		  { 18 E2 2D 00 00 00 00 00 ?? ?? 00 00 01 00 00 80 ?? ?? 00 00 ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 E2 2D 00 00 00 00 00 ?? ?? 00 00 01 00 00 80 ?? ?? 00 00 ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
    $header = { 18 E2 2D 00 00 00 00 00 ?? ?? 00 00 01 00 00 80 ?? ?? 00 00 ?? }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_SQLITE_WAL {
  meta:
    description   = "Detects SQLite Write-Ahead Log (.db-wal) files"
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $signature_1 = { 37 7F 06 82 00 2D E2 18 00 00 }

  condition:
    $signature_1 at 0
}

rule vigilantx_file_detect_magic_LINUX_I386_OBJECT_FILE {
  meta:
    description   = "Detects Linux/i386 object files (.xlog)"
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $signature_1 = { 07 01 00 }  // Характерная подпись в начале файла

  condition:
    $signature_1 at 0
}

rule vigilantx_file_detect_magic_PDP11_KERNEL_OVERLAY {
  meta:
    description   = "Detects PDP-11 kernel overlay files (general rule)"
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $signature = { 1F 01 00 00 }  // Характерная подпись PDP-11 kernel overlay

  condition:
    $signature at 0  // Проверка наличия сигнатуры в начале файла
}

rule vigilantx_file_detect_magic_ADOBE_COLOR_SWATCH {
  meta:
    description   = "Detects Adobe Photoshop Color Swatch files (.aco)"
    author        = "xCEVre"
    date          = "2025-04-01"
    severityLevel = "INFORMATIONAL"

  strings:
    $header_version = { 00 00 00 04 }  // Количество цветов (4)
    $header_info    = { 00 00 00 03 }  // Версия или другой параметр
    $swatch_bytes   = "Map_Painter_S_6"

  condition:
    $header_version at 0 and $header_info and $swatch_bytes  // Проверка заголовка и байтовой последовательности
}

rule vigilantx_file_detect_magic_MP3 {
  meta:
    description = "Detects MP3 files (MPEG Audio Layer III)"
    author      = "xCEVre"
    date        = "2025-04-01"

  strings:
    $id3_header = { 49 44 33 ?? ?? ?? }  // ID3 с любой версией

  condition:
    $id3_header at 0
}

rule vigilantx_file_detect_magic_Flash_Player_Locale {
  meta:
    description = "Detects Flash Player localization files"
    author      = "xCEVre"
    date        = "2025-04-01"
    reference   = "Adobe Flash Player Localizable Strings"

  strings:
    $header = { FF FE 2F 00 2A 00 2A 00 2A 00 2A 00 }  // UTF-16 BOM + comment block

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_PE {
  meta:
    description = "Detects generic PE (Portable Executable) files"
    author      = "xCEVre"
    date        = "2025-04-01"
    reference   = "PE file format signature"

  strings:
    $mz_header   = "MZ"  // "MZ" header for PE files
    $pe_header   = { 50 45 00 00 }  // "PE\0\0" signature
    $dos_message = "This program cannot be run in DOS mode." ascii

  condition:
    $mz_header at 0 and $pe_header in (0..0x200) and $dos_message
}

rule vigilantx_file_detect_magic_PE_TOTAL {
  meta:
    description = "Detects generic PE (Portable Executable) files"
    author      = "xCEVre"
    date        = "2025-04-01"
    reference   = "PE file format signature"

  strings:
    $header = { 4D 5A ?? 00 ?? 00 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 00 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 ?? }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_MAC_OS_X_ICON {
  meta:
    description = "Detects Apple ICNS (icon) files"
    author      = "xCEVre"
    date        = "2025-04-01"
    reference   = "ICNS file format signature"

  strings:
    $icns_header = "icns"  // file signature
    $toc_entry   = "TOC "  // Table of Contents entry

  condition:
    $icns_header at 0 and $toc_entry in (0..0x100)
}

rule vigilantx_file_detect_magic_MAC_OS_X_MachO {
  meta:
    description = "Detects Mach-O executable files"
    author      = "xCEVre"
    date        = "2025-04-01"
    reference   = "Mach-O file format signature"

  strings:
    $mach_o_fat = { CA FE BA BE 00 00 00 01 }  // Mach-O Fat Binary magic
    $mach_o_64  = { CF FA ED FE 07 00 00 01 }  // Mach-O 64-bit magic

  condition:
    $mach_o_fat at 0 or $mach_o_64 at 0
}

rule vigilantx_file_detect_magic_MAC_OS_X_Binary_Property_List {
  meta:
    description = "Detects Apple Binary Property List (bplist) files"
    author      = "xCEVre"
    date        = "2025-04-01"
    reference   = "Binary Property List format signature"

  strings:
    $bplist_header = "bplist00"

  condition:
    $bplist_header at 0
}

rule vigilantx_file_detect_magic_MAC_OS_X_CodeResources_File {
  meta:
    description = "Detects Apple CodeResources files used for code signing"
    author      = "xCEVre"
    date        = "2025-04-01"
    reference   = "Apple CodeResources signature format"

  strings:
    $code_resources_magic = { 73 38 63 68 01 00 00 00 }  // "s8ch" magic signature

  condition:
    $code_resources_magic at 0
}

rule vigilantx_file_detect_magic_MAC_OS_X_NSHumanReadableCopyright_utf16 {
  meta:
    description = "Detects files containing NSHumanReadableCopyright in UTF-16 encoding"
    author      = "xCEVre"
    date        = "2025-04-01"

  strings:
    $copyright_text = {
      ff fe fe ff 00 0a 00 4e 00 53 00 48 00 75 00 6d  //
      00 61 00 6e 00 52 00 65 00 61 00 64 00 61 00 62  //
      00 6c 00 65 00 43 00 6f 00 70 00 79 00 72 00 69  //
      00 67 00 68 00 74 00 20 00 3d 00 20 00 22 00 43  //
      00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74
    }

  condition:
    $copyright_text
}

rule vigilantx_file_detect_magic_MAC_OS_X_Plist {
  meta:
    description   = "Checks for the presence of XML declaration and DOCTYPE plist"
    author        = "xCEVre"
    date          = "2025-04-01"
    last_modified = "2025-03-21"

  strings:
    $xml_declaration = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    $doctype_plist   = "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"

  condition:
    $xml_declaration at 0 and $doctype_plist
}

rule vigilantx_file_detect_magic_MAC_OS_X_PkgInfo {
  meta:
    description = "Detects Apple CodeResources files used for code signing"
    author      = "xCEVre"
    date        = "2025-04-01"

  strings:
    $magic   = "APPLSWF2"
    $magic_2 = "APPLSWF1"
    $magic_3 = "APPLSIGN"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_fontconfig_cache {
  meta:
    description = "Detects fontconfig cache file: le64-9"
    author      = "xCEVre"
    date        = "2025-04-01"

  strings:
    $header = { 04 FC 02 FC 09 00 00 00 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_AVIF {
  meta:
    description = "Detects AVIF (AV1 Image File Format) files"
    author      = "xCEVre"
    date        = "2025-04-01"

  strings:
    // Сигнатура в начале AVIF файла: "ftypavif"
    $avif_header = "ftypavif"

  condition:
    // Проверяем, что сигнатура находится в начале файла
    $avif_header at 4
}

rule vigilantx_file_detect_magic_PNG {
  meta:
    author      = "xCEVre"
    description = "Detects PNG files by their magic bytes"

  strings:
    $png_header = { 89 50 4E 47 0D 0A 1A 0A }  // Магические байты PNG    

  condition:
    $png_header at 0  // Проверяем, что сигнатура находится в начале файла
}

rule vigilantx_file_detect_magic_OPUS_OGG {
  meta:
    description = "Detects Opus audio files in Ogg format"
    date        = "2025-04-01"

  strings:
    $opus_magic = "OggS"

  condition:
    // Файл должен начинаться с сигнатуры Ogg
    $opus_magic at 0
}

rule vigilantx_file_detect_magic_JPEG {
  meta:
    description = "Обнаружение JPEG-файлов"

  strings:
    $jpeg_soi = { FF D8 FF }  // Начало файла JPEG (SOI)

  condition:
    $jpeg_soi at 0
}

rule vigilantx_file_detect_magic_JPEG_with_GPS {
  meta:
    description = "Поиск JPEG-файлов с GPS-координатами"

  strings:
    $app1_exif = { FF E1 ?? ?? 45 78 69 66 00 00 }  // APP1 (Exif), метка "Exif\0\0"
    $gps_ifd   = { 88 25 }  // Тег GPS IFD (0x8825)
    $gps_lat   = { 00 02 00 05 }  // Тег GPSLatitude (0x0002)
    $gps_long  = { 00 04 00 05 }  // Тег GPSLongitude (0x0004)

  condition:
    vigilantx_file_detect_magic_JPEG and all of them
}

rule vigilantx_file_detect_magic_JPEG_with_GPS_ALT {
  meta:
    description = "Поиск JPEG-файлов с GPS-координатами (+ высота)"

  strings:
    $gps_alt = { 00 06 00 05 }  // Тег GPSAltitude (0x0006)

  condition:
    vigilantx_file_detect_magic_JPEG_with_GPS and $gps_alt
}

rule vigilantx_file_detect_magic_MP4 {
  meta:
    author      = "xCEVre"
    description = "Detects MP4 files by their magic bytes"

  strings:
    $mp4_isom = "ftypisom"
    $mp4_msnv = "ftypMSNV"
    $mp4_mp42 = "ftypmp42"

  condition:
    any of them at 4
}

rule vigilantx_file_detect_magic_SWF {
  meta:
    author      = "xCEVre"
    description = "Detects Adobe Flash SWF files by their magic bytes"

  strings:
    $swf_compressed   = "CWS"  // "CWS" - Сжатый SWF
    $swf_uncompressed = "FWS"  // "FWS" - Несжатый SWF

  condition:
    $swf_compressed at 0 or $swf_uncompressed at 0
}

rule vigilantx_file_detect_magic_WOFF {
  meta:
    author      = "xCEVre"
    description = "Detects WOFF font files"

  strings:
    $woff  = "wOFF"
    $woff2 = "wOF2"

  condition:
    $woff at 0 or $woff2 at 0
}

rule vigilantx_file_detect_magic_TORRENT {
  meta:
    description = "Detects torrent files based on Bencode structure"
    author      = "xCEVre"

  strings:
    $bencode_info          = "d4:info"
    $bencode_piece_length  = "6:pieces_length"
    $bencode_comment       = "d7:comment"
    $bencode_announce      = "d8:announce"
    $bencode_created_by    = "d10:created by"
    $bencode_announce_list = "d13:announce-list"

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_PDF {
  meta:
    description = "Detects PDF files based on magic number and EOF marker"
    author      = "xCEVre"
    date        = "2025-04-01"
    version     = "1.0"

  strings:
    $pdf_magic = "%PDF-"

  condition:
    $pdf_magic at 0
}

rule vigilantx_file_detect_magic_X509_Cert {
  meta:
    author      = "xCEVre"
    description = "Detects DER and PEM encoded X.509 certificates"

  strings:
    $der_cert = { 30 82 }  // DER-encoded certificate
    $pem_cert = "-----BEGIN CERTIFICATE-----"

  condition:
    $der_cert at 0 or $pem_cert at 0
}

rule vigilantx_file_detect_magic_X509_CSR {
  meta:
    author        = "xCEVre"
    description   = "Detects PEM encoded X.509 Certificate Signing Request (CSR)"
    severityLevel = "INFORMATIONAL"

  strings:
    $csr = "-----BEGIN CERTIFICATE REQUEST-----"

  condition:
    $csr at 0
}

rule vigilantx_file_detect_magic_SSH_Public_Key {
  meta:
    author        = "xCEVre"
    description   = "Detects OpenSSH public key files"
    severityLevel = "INFORMATIONAL"

  strings:
    $ssh_pub = "-----BEGIN SSH2 KEY-----"

  condition:
    $ssh_pub at 0
}

rule vigilantx_file_detect_magic_PKCS8_Private_Key {
  meta:
    author      = "xCEVre"
    description = "Detects PEM encoded PKCS#8 private keys"

  strings:
    $pkcs8_key = "-----BEGIN PRIVATE KEY-----"

  condition:
    $pkcs8_key at 0
}

rule vigilantx_file_detect_magic_RSA_Private_Key {
  meta:
    author      = "xCEVre"
    description = "Detects PEM encoded RSA private keys"

  strings:
    $rsa_key = "-----BEGIN REA PRIVATE KEY-----"

  condition:
    $rsa_key at 0
}

rule vigilantx_file_detect_magic_DSA_Private_Key {
  meta:
    author      = "xCEVre"
    description = "Detects PEM encoded DSA private keys"

  strings:
    $dsa_key = "-----BEGIN DSA PRIVATE KEY-----"

  condition:
    $dsa_key at 0
}

rule vigilantx_file_detect_magic_OpenSSH_Private_Key {
  meta:
    author      = "xCEVre"
    description = "Detects OpenSSH private keys"

  strings:
    $openssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----"

  condition:
    $openssh_key at 0
}

rule vigilantx_file_detect_magic_PuTTY_Private_Key_V2 {
  meta:
    author      = "xCEVre"
    description = "Detects PuTTY private key file version 2"

  strings:
    $putty_v2 = "PuTTY-User-Key-File-2:"

  condition:
    $putty_v2 at 0
}

rule vigilantx_file_detect_magic_PuTTY_Private_Key_V3 {
  meta:
    author      = "xCEVre"
    description = "Detects PuTTY private key file version 3"

  strings:
    $putty_v3 = "PuTTY-User-Key-File-3:"

  condition:
    $putty_v3 at 0
}

rule vigilantx_file_detect_magic_GZIP {
  meta:
    author      = "xCEVre"
    description = "Detects GZIP compressed files by their magic bytes"

  strings:
    $header = { 1F 8B }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_XZ {
  meta:
    author        = "xCEVre"
    description   = "Detects XZ compressed files by their magic bytes"
    severityLevel = "ARCHIVE"

  strings:
    $header = { FD 37 7A 58 5A 00 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_LZ4 {
  meta:
    author        = "xCEVre"
    description   = "Detects LZ4 compressed files by their magic bytes"
    severityLevel = "ARCHIVE"

  strings:
    $header = { 04 22 4D 18 }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_CAB {
  meta:
    author      = "xCEVre"
    description = "Detects Microsoft Cabinet files by their magic bytes"

  strings:
    $header = "MSCF"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_7Z {
  meta:
    author      = "xCEVre"
    description = "Detects 7-Zip archive files by their magic bytes"

  strings:
    $header = { 37 7A BC AF 27 1C }  // 7z¼¯'

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_Matroska {
  meta:
    author        = "xCEVre"
    description   = "Detects Matroska media container files (MKV, MKA, MKS, MK3D, WebM)"
    severityLevel = "INFORMATIONAL"

  strings:
    $header = { 1A 45 DF A3 }  // EBML заголовок Matroska

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_DER {
  meta:
    author      = "xCEVre"
    description = "Detects DER-encoded X.509 certificates"

  strings:
    $header = { 30 82 }  // ASN.1 DER-формат

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_WASM {
  meta:
    author      = "xCEVre"
    description = "Detects WebAssembly binary files by their magic bytes"

  strings:
    //			{ 00 61 73 6D 01 00 00 00 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7F ?? ?? ?? ?? ?? ?? 7F ?? ?? ?? ?? ?? }
    $header = { 00 61 73 6D }  // "asm" — WebAssembly magic header

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_LeptonJPEG {
  meta:
    author        = "xCEVre"
    description   = "Detects Lepton compressed JPEG images by their magic bytes"
    severityLevel = "INFORMATIONAL"

  strings:
    $header = { CF 84 01 }  // Lepton JPEG magic header

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_RTF {
  meta:
    author      = "xCEVre"
    description = "Detects Rich Text Format (RTF) files by their magic bytes"

  strings:
    $header = "{\\rtf1"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_GIF {
  meta:
    author        = "xCEVre"
    description   = "Detects GIF files by their magic bytes"
    severityLevel = "INFORMATIONAL"

  strings:
    $header = "GIF8"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_ZIP {
  meta:
    author        = "xCEVre"
    description   = "Detects files that contain the ZIP magic number (PK..)"
    date          = "2025-04-01"
    severityLevel = "ARCHIVE"

  condition:
    uint32be(0) == 0x504B0304  // { 50 4B 03 04 }
}

rule vigilantx_file_detect_magic_MPEG_Program_Stream {
  meta:
    author      = "xCEVre"
    description = "Detects MPEG Program Stream files (MPEG-1 Part 1 and MPEG-2 Part 1)"

  condition:
    uint32be(0) == 0x000001BA  // { 00 00 01 BA }
}

rule vigilantx_file_detect_magic_MPEG_Video {
  meta:
    author      = "xCEVre"
    description = "Detects MPEG-1 and MPEG-2 video files by their magic bytes"

  strings:
    $header_2 = { 00 00 01 B3 }  // MPEG-1 video and MPEG-2 video header

  condition:
    $header_2 at 0
}

rule vigilantx_file_detect_magic_Roblox_Place {
  meta:
    author      = "xCEVre"
    description = "Detects Roblox place file (rbxl) by magic bytes"

  strings:
    $header = "<roblox!"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_Lua_Bytecode {
  meta:
    author      = "xCEVre"
    description = "Detects Lua bytecode file (luac) by magic bytes"

  strings:
    $header = { 1B 4C 75 61 }  // Lua bytecode magic number

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_PGP {
  meta:
    author      = "xCEVre"
    description = "Detects PGP file by magic bytes"

  strings:
    $pgp_header = { 85 ?? ?? 03 }  // PGP file magic bytes

  condition:
    $pgp_header at 0
}

rule vigilantx_file_detect_magic_Zstandard {
  meta:
    author      = "xCEVre"
    description = "Detects Zstandard compressed file by magic bytes"

  strings:
    $zst_header = { 28 B5 2F FD }  // Zstandard compression magic bytes

  condition:
    $zst_header at 0
}

rule vigilantx_file_detect_magic_QCOW {
  meta:
    author      = "xCEVre"
    description = "Detects QCOW file by magic bytes"

  strings:
    $qcow_header = "QFI"

  condition:
    $qcow_header at 0
}

rule vigilantx_file_detect_magic_FLV {
  meta:
    author      = "xCEVre"
    description = "Detects FLV (Flash Video) file by magic bytes"

  strings:
    $flv_header = "FLV"

  condition:
    $flv_header at 0
}

rule vigilantx_file_detect_magic_VDI {
  meta:
    author      = "xCEVre"
    description = "Detects VirtualBox Virtual Hard Disk (VDI) file by magic string"

  strings:
    $vdi_header = "<<< Oracle VM VirtualBox Disk Image >>>"

  condition:
    $vdi_header at 0
}

rule vigilantx_file_detect_magic_VHD {
  meta:
    author      = "xCEVre"
    description = "Detects Windows Virtual PC Virtual Hard Disk (VHD) file by magic string"

  strings:
    $vhd_header = "conectix"

  condition:
    $vhd_header at 0
}

rule vigilantx_file_detect_magic_VHDX {
  meta:
    author      = "xCEVre"
    description = "Detects Windows Virtual PC Windows 8 Virtual Hard Disk (VHDX) file by magic string"

  strings:
    $vhdx_header = "vhdxfile"

  condition:
    $vhdx_header at 0
}

rule vigilantx_file_detect_magic_ISZ {
  meta:
    author      = "xCEVre"
    description = "Detects ISZ (Compressed ISO image) file by magic string"

  strings:
    $isz_header = "IsZ!"

  condition:
    $isz_header at 0
}

rule vigilantx_file_detect_magic_DAA {
  meta:
    author      = "xCEVre"
    description = "Detects DAA (Direct Access Archive) file by magic string"

  strings:
    $daa_header = "DAA"

  condition:
    $daa_header at 0
}

rule vigilantx_file_detect_magic_EVT {
  meta:
    author      = "xCEVre"
    description = "Detects EVT (Windows Event Viewer file) by magic string"

  strings:
    $evt_header = "LfLe"

  condition:
    $evt_header at 0
}

rule vigilantx_file_detect_magic_EVTX {
  meta:
    author      = "xCEVre"
    description = "Detects EVTX (Windows Event Viewer XML file) by magic string"

  strings:
    $evtx_header = "ElfFile"

  condition:
    $evtx_header at 0
}

rule vigilantx_file_detect_magic_BLEND {
  meta:
    author      = "xCEVre"
    description = "Detects Blender file format by magic string"

  strings:
    $blender_header = "BLENDER"

  condition:
    $blender_header at 0
}

rule vigilantx_file_detect_magic_JXL {
  meta:
    author      = "xCEVre"
    description = "Detects JPEG XL (JXL) image format by magic string"

  strings:
    $jxl_header_1 = { 00 00 00 0C 4A 58 4C 20 0D 0A 87 0A }  // First magic sequence for JXL
    $jxl_header_2 = { FF 0A }  // Second magic sequence for JXL

  condition:
    ($jxl_header_1 at 0 or $jxl_header_2 at 0)
}

rule vigilantx_file_detect_magic_TTF {
  meta:
    author      = "xCEVre"
    description = "Detects TrueType font (TTF), TrueType collection (TTC), and dfont by magic bytes"

  strings:
    $ttf_header   = { FF 0A }  // TrueType font magic bytes
    $ttf_header_2 = { 00 01 00 00 00 }  // Alternative TTF header

  condition:
    $ttf_header at 0 or $ttf_header_2 at 0
}

rule vigilantx_file_detect_magic_OTF {
  meta:
    author        = "xCEVre"
    description   = "Detects OpenType font (OTF) by magic bytes"
    severityLevel = "INFORMATIONAL"

  strings:
    $otf_header = "OTTO"

  condition:
    $otf_header at 0
}

rule vigilantx_file_detect_magic_Modulefile {
  meta:
    author      = "xCEVre"
    description = "Detects Modulefile for Environment Modules"

  strings:
    $modulefile_header = "#%Module"

  condition:
    $modulefile_header at 0
}

rule vigilantx_file_detect_magic_VBE {
  meta:
    author      = "xCEVre"
    description = "Detects VBScript Encoded script (VBE) by magic bytes"

  strings:
    $vbe_header = "#@~^"

  condition:
    $vbe_header at 0
}

rule vigilantx_file_detect_magic_CDB {
  meta:
    author      = "xCEVre"
    description = "Detects MikroTik WinBox Connection Database (CDB) by magic bytes"

  strings:
    $cdb_header = { 0D F0 1D C0 }  // MikroTik WinBox Connection Database header

  condition:
    $cdb_header at 0
}

rule vigilantx_file_detect_magic_M3U {
  meta:
    author        = "xCEVre"
    description   = "Detects Multimedia playlist (M3U, M3U8) files by magic bytes"
    severityLevel = "INFORMATIONAL"

  strings:
    $m3u_header = "#EXTM3U"

  condition:
    $m3u_header at 0
}

rule vigilantx_file_detect_magic_PGP_Public_Key {
  meta:
    author        = "xCEVre"
    description   = "Detects Armored PGP public key by magic bytes"
    severityLevel = "INFORMATIONAL"

  strings:
    $pgp_header = "-----BEGIN PGP PUBLIC KEI BLOCK-----"

  condition:
    $pgp_header at 0
}

rule vigilantx_file_detect_magic_MESA_shader_CACHE_DB {
  meta:
    author        = "xCEVre"
    description   = "Detects mesa shader cache .{db,idx} "
    severityLevel = "INFORMATIONAL"

  strings:
    $header = { 4D 45 53 41 5F 44 42 00 }  // "MESA_DB\0"

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_m4v {
  meta:
    author      = "xCEVre"
    description = "Detects video .m4v "
    date        = "2025-07-01"

  strings:
    $m4v_header = { 00 00 00 1C 66 74 79 70 4D 34 56 20 }

  condition:
    $m4v_header at 0
}

rule vigilantx_file_detect_magic_zlib {
  meta:
    author      = "xCEVre"
    description = "Detects zlib compression with no compression and no preset dictionary"

  strings:
    $header_1 = { 78 01 }  // zlib No Compression (no preset dictionary)
    $header_2 = "x "  // zlib No compression (with preset dictionary)
    $header_3 = "x^"  // zlib Best speed (no preset dictionary)
    $header_4 = "x}"  // zlib Best speed (with preset dictionary)
    $header_5 = { 78 9C }  // zlib Default compression (no preset dictionary)
    $header_6 = { 78 BB }  // zlib Default compression (with preset dictionary)
    $header_7 = { 78 DA }  // zlib Best compression (no preset dictionary)
    $header_8 = { 78 F9 }  // zlib Best compression (with preset dictionary)

  condition:
    (filesize >= 6) and (any of them at 0)
}

