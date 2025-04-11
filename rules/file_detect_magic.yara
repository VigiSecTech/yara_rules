
// enum severityLevel:
//	INFORMATIONAL, // Просто информация, нет угрозы
//	LOW,           // Минимальный риск
//	MEDIUM,        // Средний уровень риска
//	HIGH,          // Значительный риск
//	CRITICAL       // Критическая угроза
//
//	ARCHIVE       // Используется для хранилищ (архивы и тд)
//	UNKNOWN       // Не известно


rule file_detect_magic_archive_FreeArc{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "ARCHIVE"
        description = "Detects 'FreeArc archive <http://freearc.org>' files"
    strings:
        $magic_tiny = { 41 72 43 01 }
        $magic_huge = { 41 72 43 01 00 00 06 07 41 72 43 01 02 73 74 6F 72 69 6E 67 00 10 10 11 55 33 BC 10 12 71 82 44 48 28 EE 1F }
    condition:
        any of them at 0
}

rule file_detect_magic_SHEBANG_ENV_BASH{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "LOW"
        description = "Detects 'Bourne-Again shell script' files"
    strings:
        $header = { 23 21 2F 75 73 72 2F 62 69 6E 2F 65 6E 76 20 62 61 73 68 } // '#!/usr/bin/env bash'
    condition:
        $header at 0
}

rule file_detect_magic_SVG{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "INFORMATIONAL"
        description = "Detects 'SVG Scalable Vector Graphics image' files"
    strings:
        $header = { 3C 73 76 67 20 ?? ?? ?? ?? ?? }
    condition:
        $header at 0
}


rule file_detect_magic_CRYPTO_PEM_RSA_PRIVATE_KEY{
    meta:
        author = "xCEVre"
        date = "2025-04-05"
        severityLevel= "INFORMATIONAL"
        description = "Detects (PEM RSA private key) files"
    strings:
        $header = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 52 53 41 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D }
    condition:
        $header at 0
}
rule file_detect_magic_CRYPTO_PEM_CERTIFICATE{
    meta:
        author = "xCEVre"
        date = "2025-04-05"
        severityLevel= "INFORMATIONAL"
        description = "Detects PEM certificate files"
    strings:
        $start = { 2d 2d 2d 2d 2d 42 45 47  49 4e 20 43 45 52 54 49 46 49 43 41 54 45 2d 2d  2d 2d 2d }
        $end = { 2d 2d 2d 2d 2d 45 4e 44  20 43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d  2d }
    condition:
        any of them
}
rule file_detect_magic_CRYPTO_DH_PARAMETERS{
    meta:
        author = "xCEVre"
        date = "2025-04-05"
        severityLevel= "INFORMATIONAL"
        description = "Detects files with DH PARAMETERS"
    strings:
        $start = { 2d 2d 2d 2d 2d 42 45 47  49 4e 20 44 48 20 50 41 52 41 4d 45 54 45 52 53  2d 2d 2d 2d 2d }
        $end = { 2d 2d 2d 2d 2d 45 4e 44  20 44 48 20 50 41 52 41 4d 45 54 45 52 53 2d 2d  2d 2d 2d }
    condition:
        any of them
}

rule file_detect_magic_ELF{
    meta:
        author = "xCEVre"
        date = "2025-04-05"
        severityLevel= "UNKNOWN"
        description = "Detects ELF files"
    strings:
        $header = { 7F 45 4C 46 }
    condition:
        $header at 0
}



rule file_detect_magic_SpaceRangersHD_Save{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "INFORMATIONAL"
        description = "Detects '.sav' files"
    strings:
        $header = { 52 00 53 00 47 00 00 00 76 00 31 00 36 00 37 00 00 00 }
    condition:
        $header at 0
}




rule file_detect_magic_MPEG_1_LAYER_3_MP3{
    meta:
        author = "xCEVre"
        date = "2025-04-04"
        severityLevel= "INFORMATIONAL"
        description = "Detects '.mp3' files"
    strings:
        $header_ = { FF F3 C0 CC 00 }
        $header_ = { FF F3 C8 C4 00 }
        $header_ = { FF FB 90 C4 00 }
        $header_ = { FF FB B0 44 00 }
    condition:
        any of them at 0
}

rule file_detect_magic_APPLE_DESKTOP_SERVICES_STORE{
    meta:
        author = "xCEVre"
        date = "2025-04-04"
        severityLevel= "INFORMATIONAL"
        description = "Detects '.DS_Store' files"
    strings:
        $header = { 00 00 00 01 42 75 64 31 00 00 }
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

rule file_detect_magic_UNITY_LEVEL{
    meta:
        author = "xCEVre"
        date = "2025-04-04"
        severityLevel= "INFORMATIONAL"
        description = "Detects levelX files"
    strings:
        $header = { 00 00 00 00 00 00 00 00 00 00 00 16 00 00 00 00 00 00 00 00 00  }
    condition:
        $header at 0
}
rule file_detect_magic_UNITY_resource{
    meta:
        author = "xCEVre"
        date = "2025-04-04"
        severityLevel= "INFORMATIONAL"
        description = "Detects '.resource' files"
    strings:
        $header = { 46 53 42 35 01 00 00 00 01 00 00 00  }
    condition:
        $header at 0
}

rule file_detect_magic_WINE_REG_V2{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "INFORMATIONAL"
        description = "Detects wine registry file with extension '.reg'"
    strings:
        $header = { 57 49 4E 45 20 52 45 47 49 53 54 52 59 20 56 65 72 73 69 6F 6E 20 32 }
    condition:
        $header at 0
}


rule file_detect_magic_MS_Windows_Icon_Resource{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "INFORMATIONAL"
        description = "Detects 'MS Windows icon resource' files extension '.ico'"
    strings:
        $header = { 00 00 01 00 ?? 00 ?? ?? ?? 00 01 00 ?? }
    condition:
        any of them at 0
}
rule file_detect_magic_MS_Window_Setup_INFormation{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "INFORMATIONAL"
        description = "Detects 'Windows setup INFormation' files extension '.inf'"
    strings:
        $header_0 = { 5B 56 65 72 73 69 6F 6E 5D 0A 53 69 67 6E 61 74 75 72 65 3D 22 24 43 48 49 43 41 47 4F 24 22 } // [Version] \n Signature="$CHICAGO$"
        $header_1 = { 5B 56 65 72 73 69 6F 6E 5D 0A 53 69 67 6E 61 74 75 72 65 3D 22 24 43 48 49 43 41 47 4F 24 22 0A 43 6C 61 73 73 47 75 69 64 3D 7B } // [Version] \n Signature="$CHICAGO$" \n ClassGuid={
    condition:
        any of them at 0
}


rule file_detect_magic_UNKNOWN_1_dat{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "UNKNOWN"
        description = "Detects UNKNOWN files extension '.dat'"
    strings:
        $header_1 = { 53 54 52 47 01 00 00 00 5A }
    condition:
        any of them at 0
}
rule file_detect_magic_UNKNOWN_1_bin{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "UNKNOWN"
        description = "Detects UNKNOWN files extension '.bin'"
    strings:
        $header_1 = { 00 63 61 63 68 65 00 02 63 72 63 00 }
    condition:
        any of them at 0
}
rule file_detect_magic_UNKNOWN_foz{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "UNKNOWN"
        description = "Detects UNKNOWN files extension '.foz'"
    strings:
        $header_1 = { 81 46 4F 53 53 49 4C 49 5A 45 44 42 00 00 00 06 }
    condition:
        any of them at 0
}

rule file_detect_magic_UNKNOWN_ZeroS{
    meta:
        author = "xCEVre"
        date = "2025-04-11"
        severityLevel= "UNKNOWN"
        description = "Detects UNKNOWN files regex '[a-z0-9]+_(s|0)'"
    strings:
        $ext_s = { 30 5C 72 A7 1B 6D FB FC 09 00 00 00 }
        $ext_0 = { 30 5C 72 A7 1B 6D FB FC 05 00 00 00 }
        $ext_any = { 30 5C 72 A7 1B 6D FB FC ?? 00 00 00 }
    condition:
        any of them at 0
}

rule file_detect_magic_UNKNOWN_PAK_1{
    meta:
        author = "xCEVre"
        date = "2025-04-03"
        severityLevel= "UNKNOWN"
        description = "Detects UNKNOWN files with extension '.pak' "
    strings:
        $header = { 05 00 00 00 01 00 00 00 }
    condition:
        $header at 0
}

rule file_detect_magic_RVDATA2{
    meta:
        author = "xCEVre"
        date = "2025-04-03"
        severityLevel= "INFORMATIONAL"
        description = "Detects rvdata2 files"
    strings:
        $header = { 04 08 }
    condition:
        $header at 0
}



rule file_detect_magic_RIFF {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"
        description = "Detects RIFF files"
        reference_0="https://en.wikipedia.org/wiki/Resource_Interchange_File_Format"
    strings:
        $riff_header = { 52 49 46 46 ?? ?? ?? ?? } // "RIFF"+size
    condition:
        $riff_header at 0
}

rule file_detect_magic_RIFF_AVI {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"
        description = "Detects RIFF AVI files"
    strings:
        $avi = { 41 56 49 20 4C 49 53 54 ?? ?? ?? ?? }
    condition:
		file_detect_magic_RIFF and $avi at 8
}

rule file_detect_magic_RIFF_WAV {
    meta:
        description = "Detects RIFF WAV (Wave Audio File Format) files"
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"
    strings:
        $wave_marker = { 57 41 56 45 } // "WAVE" 
    condition:
		file_detect_magic_RIFF and $wave_marker at 8
}
rule file_detect_magic_RIFF_WEBP {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"
        reference_0="https://en.wikipedia.org/wiki/WebP"
        description = "Detects WebP image files by their magic bytes"
    strings:
        $webp_header = {  57 45 42 50 } // "WEBP"
    condition:
		file_detect_magic_RIFF and $webp_header at 8
}

rule file_detect_magic_CEPACK {
    meta:
        author = "xCEVre"
        date = "2025-04-02"
        description = "Обнаружение файлов CEPACK"
		severityLevel= "UNKNOWN"
    strings:
        $header = { 43 45 50 41 43 4B }
    condition:
        $header at 0
}



rule file_detect_magic_UNKNOWN_EXT_PKG_1 {
    meta:
        author = "xCEVre"
        date = "2025-04-02"
        description = "Обнаружение не известного типа с расширением .pkg"
		severityLevel= "UNKNOWN"
    strings:
        $header = { 04 00 00 00 AA 00 00 00 01 00 00 00 9E 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? }
    condition:
        $header at 0
}

rule file_detect_magic_UNKNOWN_IMAGE_CONTAINER_1 {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        description = "Обнаружение контейнера неизвестного типа(FIXME НАЙТИ И ДОПОЛНИТЬ) с изображениями"
		severityLevel= "ARCHIVE"
    strings:
        $header_1 = { 00 00 00 00 01 00 ?? ?? ?? 00  }
        $header_2 = { 00 00 00 00 01 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 01 ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? }
    condition:
        any of them at 0
}

rule file_detect_magic_UNKNOWN_IMAGE_CONTAINER_1_pak {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        description = "Обнаружение контейнера неизвестного типа(FIXME НАЙТИ И ДОПОЛНИТЬ) с изображениями,расширение .pak"
		severityLevel= "ARCHIVE"
    strings:
        $header = { 05 00 00 00 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? ?? 00 00 ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? 00 ?? ?? }
    condition:
        $header at 0
}

rule file_detect_magic_UNKNOWN_ADS_DATA_kva {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        description = "Обнаружение файлов рекламного SDK не известной мне компании, файлы обычно имеют .kva расширение"

    strings:
        $header = { ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 06 ?? ?? ?? }
    condition:
        $header at 0
}


rule file_detect_magic_grafana_BeylaConfig {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
    strings:
        $magic = { 23 62 65 79 6C 61 5F 69 64 73 0A }
    condition:
		$magic at 0       
}

rule file_detect_magic_XML {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"

    strings:
        $xml_BOM = { EF BB BF }
        $xml_header ={ 3C 3F 78 6D 6C} // "<?xml"
    condition:
		($xml_BOM at 0 and $xml_header at 3) or ($xml_header at 0)        
}

rule file_detect_magic_HTML {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"

    strings:
        $tab_html_tag = { ?? 3C 68 74 6D 6C 3E }
        $doctype = "<!DOCTYPE" nocase wide ascii
        $html_tag = "<html" nocase wide ascii
    condition:
        any of them at 0
}



rule file_detect_magic_AllInOneOfflineMaps {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        description = "Detect generic binary navigation format containing coordinate data and application metadata"
        severityLevel= "INFORMATIONAL"

    strings:
        $header = { 50 50 ?? 01 00 00 ?? ?? ?? ?? ?? ?? 00 00 00 ?? } 
    condition:
        $header at 0
}

rule file_detect_magic_AllInOneOfflineMaps_WPT {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"
    strings:
        $header = { 0A } // третий байт сигнализирующий что файл должен иметь формат ".wpt"
    condition:
        file_detect_magic_AllInOneOfflineMaps and $header at 2
}

rule file_detect_magic_AllInOneOfflineMaps_ARE {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"
    strings:
        $header = { 0D } // третий байт сигнализирующий что файл должен иметь формат ".are"
    condition:
        file_detect_magic_AllInOneOfflineMaps and $header at 2
}
rule file_detect_magic_AllInOneOfflineMaps_RTE {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"
    strings:
        $header = { 0C } // третий байт сигнализирующий что файл должен иметь формат ".are"
    condition:
        file_detect_magic_AllInOneOfflineMaps and $header at 2
}
rule file_detect_magic_AllInOneOfflineMaps_TRK {
    meta:
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"
    strings:
        $header = { 0e } // третий байт сигнализирующий что файл должен иметь формат ".are"
    condition:
        file_detect_magic_AllInOneOfflineMaps and $header at 2
}










rule file_detect_magic_SQLITE3 {
    meta:
        description = "Detects SQLite version 3 database files"
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"

    strings:
        $magic_header = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 } // "SQLite format 3\0"

    condition:
        $magic_header at 0
}
rule file_detect_magic_SQLITE3_SHM {
    meta:
        description = "Detects SQLite Write-Ahead Log shared memory (.db-shm) files"
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"

    strings:
		// 		  { 18 E2 2D 00 00 00 00 00 ?? ?? 00 00 01 00 00 80 ?? ?? 00 00 ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 E2 2D 00 00 00 00 00 ?? ?? 00 00 01 00 00 80 ?? ?? 00 00 ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
        $header = { 18 E2 2D 00 00 00 00 00 ?? ?? 00 00 01 00 00 80 ?? ?? 00 00 ?? }

    condition:
		$header at 0
}
rule file_detect_magic_SQLITE_WAL {
    meta:
        description = "Detects SQLite Write-Ahead Log (.db-wal) files"
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"

    strings:
        $signature_1 = { 37 7F 06 82 00 2D E2 18 00 00 }

    condition:
        $signature_1 at 0
}




rule file_detect_magic_LINUX_I386_OBJECT_FILE {
    meta:
        description = "Detects Linux/i386 object files (.xlog)"
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"

    strings:
        $signature_1 = { 07 01 00 } // Характерная подпись в начале файла

    condition:
        $signature_1 at 0
}
rule file_detect_magic_PDP11_KERNEL_OVERLAY {
    meta:
        description = "Detects PDP-11 kernel overlay files (general rule)"
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"

    strings:
        $signature = { 1F 01 00 00 } // Характерная подпись PDP-11 kernel overlay

    condition:
        $signature at 0 // Проверка наличия сигнатуры в начале файла
}
rule file_detect_magic_ADOBE_COLOR_SWATCH {
    meta:
        description = "Detects Adobe Photoshop Color Swatch files (.aco)"
        author = "xCEVre"
        date = "2025-04-01"
        severityLevel= "INFORMATIONAL"

    strings:
        $header_version = { 00 00 00 04 } // Количество цветов (4)
        $header_info = { 00 00 00 03 }    // Версия или другой параметр
        $swatch_bytes = { 4d 61 70 5f 50 61 69 6e 74 65 72 5f 53 5f 36 } // Байты для Map_Painter_S_6

    condition:
        $header_version at 0 and $header_info and $swatch_bytes // Проверка заголовка и байтовой последовательности
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////// JAVA
////////////////////////////////////////////////////////////////////////////////////////////////////////////
rule file_detect_magic_JAVA_SER {
    meta:
        description = "Detects Java serialized object files of any version at the beginning of the file"
        author = "xCEVre"
        date = "2025-04-01"

    strings:
        $version_1 = { AC ED 00 01 } // Версия 1
        $version_2 = { AC ED 00 02 } // Версия 2
        $version_3 = { AC ED 00 03 } // Версия 3
        $version_4 = { AC ED 00 04 } // Версия 4
        $version_5 = { AC ED 00 05 } // Версия 5 (самая распространенная)
        $version_6 = { AC ED 00 06 } // Версия 6
        $version_7 = { AC ED 00 07 } // Версия 7

    condition:
        any of them at 0
}

rule file_detect_magic_JAVA_CLASS {
    meta:
        description = "Detects Java class file"
        author = "xCEVre"
        date = "2025-04-05"

    strings:
        $magic = { CA FE BA BE 00 00 00 }

    condition:
        $magic at 0
}
rule file_detect_magic_JAVA_CLASS_v8 {
    meta:
        description = "Detects Java 1.8 class file"
        author = "xCEVre"
        date = "2025-04-05"

    strings:
        $magic = { CA FE BA BE 00 00 00 34 }
    condition:
        $magic at 0
}
rule file_detect_magic_JAVA_CLASS_v21 {
    meta:
        description = "Detects Java 21 class file"
        author = "xCEVre"
        date = "2025-04-05"
    strings:
        $magic = { CA FE BA BE 00 00 00 41 }
    condition:
        $magic at 0
}
rule file_detect_magic_JAVA_CLASS_v23 {
    meta:
        description = "Detects Java 23 class file"
        author = "xCEVre"
        date = "2025-04-05"
    strings:
        $magic = { CA FE BA BE 00 00 00 43 }
    condition:
        $magic at 0
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////// JAVA
////////////////////////////////////////////////////////////////////////////////////////////////////////////

rule file_detect_magic_MP3
{
    meta:
        description = "Detects MP3 files (MPEG Audio Layer III)"
        author = "xCEVre"
        date = "2025-04-01"

    strings:
        $id3_header = { 49 44 33 ?? ?? ?? } // ID3 с любой версией

    condition:
        $id3_header at 0
}

rule file_detect_magic_Flash_Player_Locale {
    meta:
        description = "Detects Flash Player localization files"
        author = "xCEVre"
        date = "2025-04-01"
        reference = "Adobe Flash Player Localizable Strings"
    strings:
        $header = { FF FE 2F 00 2A 00 2A 00 2A 00 2A 00 }  // UTF-16 BOM + comment block
    condition:
        $header at 0
}

rule file_detect_magic_PE {
    meta:
        description = "Detects generic PE (Portable Executable) files"
        author = "xCEVre"
        date = "2025-04-01"
        reference = "PE file format signature"
    strings:
        $mz_header = { 4D 5A }  // "MZ" header for PE files
        $pe_header = { 50 45 00 00 }  // "PE\0\0" signature
        $dos_message = "This program cannot be run in DOS mode." ascii
    condition:
        $mz_header at 0 and $pe_header in (0..0x200) and $dos_message
}
rule file_detect_magic_PE_TOTAL {
    meta:
        description = "Detects generic PE (Portable Executable) files"
        author = "xCEVre"
        date = "2025-04-01"
        reference = "PE file format signature"
    strings:
        $header = { 4D 5A ?? 00 ?? 00 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 00 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 ?? }
    condition:
        $header at 0
}

rule file_detect_magic_MAC_OS_X_ICON {
    meta:
        description = "Detects Apple ICNS (icon) files"
        author = "xCEVre"
        date = "2025-04-01"
        reference = "ICNS file format signature"
    strings:
        $icns_header = { 69 63 6E 73 }  // "icns" file signature
        $toc_entry = { 54 4F 43 20 }    // "TOC " Table of Contents entry
    condition:
        $icns_header at 0 and $toc_entry in (0..0x100)
}
rule file_detect_magic_MAC_OS_X_MachO {
    meta:
        description = "Detects Mach-O executable files"
        author = "xCEVre"
        date = "2025-04-01"
        reference = "Mach-O file format signature"
    strings:
        $mach_o_fat = { CA FE BA BE 00 00 00 01 }  // Mach-O Fat Binary magic
        $mach_o_64 = { CF FA ED FE 07 00 00 01 }  // Mach-O 64-bit magic
    condition:
        $mach_o_fat at 0 or $mach_o_64 at 0
}
rule file_detect_magic_MAC_OS_X_Binary_Property_List {
    meta:
        description = "Detects Apple Binary Property List (bplist) files"
        author = "xCEVre"
        date = "2025-04-01"
        reference = "Binary Property List format signature"
    strings:
        $bplist_header = { 62 70 6C 69 73 74 30 30 }  // "bplist00" file signature
    condition:
        $bplist_header at 0
}
rule file_detect_magic_MAC_OS_X_CodeResources_File {
    meta:
        description = "Detects Apple CodeResources files used for code signing"
        author = "xCEVre"
        date = "2025-04-01"
        reference = "Apple CodeResources signature format"
    strings:
        $code_resources_magic = { 73 38 63 68 01 00 00 00 }  // "s8ch" magic signature
    condition:
        $code_resources_magic at 0
}
rule file_detect_magic_MAC_OS_X_NSHumanReadableCopyright_utf16
{
    meta:
        description = "Detects files containing NSHumanReadableCopyright in UTF-16 encoding"
        author = "xCEVre"
        date = "2025-04-01"

    strings:
        $copyright_text = { ff fe fe ff 00 0a 00 4e  00 53 00 48 00 75 00 6d
                            00 61 00 6e 00 52 00 65  00 61 00 64 00 61 00 62
                            00 6c 00 65 00 43 00 6f  00 70 00 79 00 72 00 69
                            00 67 00 68 00 74 00 20  00 3d 00 20 00 22 00 43
                            00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 }

    condition:
        $copyright_text
}
rule file_detect_magic_MAC_OS_X_Plist
{
    meta:
        description = "Checks for the presence of XML declaration and DOCTYPE plist"
        author = "xCEVre"
        date = "2025-04-01"
        last_modified = "2025-03-21"

    strings:
        $xml_declaration = { 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 22 31 2e 30 22 20 65 6e 63 6f 64 69 6e 67 3d 22 55 54 46 2d 38 22 3f 3e }
        $doctype_plist = { 3c 21 44 4f 43 54 59 50 45 20 70 6c 69 73 74 20 50 55 42 4c 49 43 20 22 2d 2f 2f 41 70 70 6c 65 2f 2f 44 54 44 20 50 4c 49 53 54 20 31 2e 30 2f 2f 45 4e 22 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 61 70 70 6c 65 2e 63 6f 6d 2f 44 54 44 73 2f 50 72 6f 70 65 72 74 79 4c 69 73 74 2d 31 2e 30 2e 64 74 64 22 3e }
        
    condition:
        $xml_declaration at 0 and $doctype_plist
}

rule file_detect_magic_MAC_OS_X_PkgInfo {
    meta:
        description = "Detects Apple CodeResources files used for code signing"
        author = "xCEVre"
        date = "2025-04-01"
    strings:
        $magic = { 41 50 50 4c 53 57 46 32 }  // "APPLSWF2" magic signature
        $magic_2 = { 41 50 50 4c 53 57 46 31 }  // "APPLSWF1" magic signature
        $magic_3 = { 41 50 50 4c 53 49 47 4e }  // "APPLSIGN" magic signature
    condition:
        any of them at 0
}


rule file_detect_magic_fontconfig_cache
{
    meta:
        description = "Detects fontconfig cache file: le64-9"	
        author = "xCEVre"
        date = "2025-04-01"

    strings:
        $header = { 04 FC 02 FC 09 00 00 00 }

    condition:
        $header at 0
}

rule file_detect_magic_AVIF
{
    meta:
        description = "Detects AVIF (AV1 Image File Format) files"
        author = "xCEVre"
        date = "2025-04-01"

    strings:
        // Сигнатура в начале AVIF файла: "ftypavif"
        $avif_header = { 66 74 79 70 61 76 69 66 } // "ftypavif" в hexadecimal

    condition:
        // Проверяем, что сигнатура находится в начале файла
        $avif_header at 4
}
rule file_detect_magic_PNG {
    meta:
        author = "xCEVre"
        description = "Detects PNG files by their magic bytes"
    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A } // Магические байты PNG    
    condition:
        $png_header at 0 // Проверяем, что сигнатура находится в начале файла
}
rule file_detect_magic_OPUS_OGG
{
    meta:
        description = "Detects Opus audio files in Ogg format"
        date = "2025-04-01"

    strings:
        $opus_magic = { 4F 67 67 53 } // "OggS"
    condition:
        // Файл должен начинаться с сигнатуры Ogg
        $opus_magic at 0
}
rule file_detect_magic_JPEG {
    meta:
        description = "Обнаружение JPEG-файлов"
    strings:
        $jpeg_soi = { FF D8 FF }            // Начало файла JPEG (SOI)
    condition:
        $jpeg_soi at 0 
}

rule file_detect_magic_JPEG_with_GPS {
    meta:
        description = "Поиск JPEG-файлов с GPS-координатами"
    strings:
        $app1_exif = { FF E1 ?? ?? 45 78 69 66 00 00 }   // APP1 (Exif), метка "Exif\0\0"
        $gps_ifd   = { 88 25 }                          // Тег GPS IFD (0x8825)
        $gps_lat   = { 00 02 00 05 }                    // Тег GPSLatitude (0x0002)
        $gps_long  = { 00 04 00 05 }                    // Тег GPSLongitude (0x0004)
    condition:
        file_detect_magic_JPEG and $app1_exif and $gps_ifd and $gps_lat and $gps_long
}


rule file_detect_magic_JPEG_with_GPS_ALT {
    meta:
        description = "Поиск JPEG-файлов с GPS-координатами (+ высота)"
    strings:
        $gps_alt   = { 00 06 00 05 }                    // Тег GPSAltitude (0x0006)
    condition:
       file_detect_magic_JPEG_with_GPS and $gps_alt
}



rule file_detect_magic_MP4 {
    meta:
        author = "xCEVre"
        description = "Detects MP4 files by their magic bytes"

    strings:
        $mp4_isom = { 66 74 79 70 69 73 6F 6D } // "ftypisom"
        $mp4_msnv = { 66 74 79 70 4D 53 4E 56 } // "ftypMSNV"
        $mp4_mp42 = { 66 74 79 70 6D 70 34 32 } // "ftypmp42"

    condition:
        any of them at 4
}


rule file_detect_magic_SWF {
    meta:
        author = "xCEVre"
        description = "Detects Adobe Flash SWF files by their magic bytes"

    strings:
        $swf_compressed   = { 43 57 53 } // "CWS" - Сжатый SWF
        $swf_uncompressed = { 46 57 53 } // "FWS" - Несжатый SWF

    condition:
        $swf_compressed at 0 or $swf_uncompressed at 0
}


rule file_detect_magic_WOFF {
    meta:
        author = "xCEVre"
        description = "Detects WOFF font files"

    strings:
        $woff  = { 77 4F 46 46 } // "wOFF"
        $woff2 = { 77 4F 46 32 } // "wOF2"

    condition:
        $woff at 0 or $woff2 at 0
}


rule file_detect_magic_TORRENT {
    meta:
        description = "Detects torrent files based on Bencode structure"
        author = "xCEVre"
    strings:
        $bencode_info = { 64 34 3A 69 6E 66 6F }  // "d4:info"
        $bencode_piece_length = { 36 3A 70 69 65 63 65 73 5F 6C 65 6E 67 74 68 }  // "6:pieces_length"
        $bencode_comment = { 64 37 3A 63 6F 6D 6D 65 6E 74 }  // "d7:comment"
        $bencode_announce = { 64 38 3A 61 6E 6E 6F 75 6E 63 65 }  // "d8:announce"
        $bencode_created_by = { 64 31 30 3A 63 72 65 61 74 65 64 20 62 79 }  // "d10:created by"
        $bencode_announce_list = { 64 31 33 3a 61 6e 6e 6f  75 6e 63 65 2d 6c 69 73 74 }  // "d13:announce-list"

    condition:
        any of them at 0
}

rule file_detect_magic_PDF
{
    meta:
        description = "Detects PDF files based on magic number and EOF marker"
        author = "xCEVre"
        date = "2025-04-01"
        version = "1.0"
        
    strings:
        $pdf_magic = { 25 50 44 46 2d }  // %PDF-
    condition:
        $pdf_magic at 0 
}





rule file_detect_magic_X509_Cert {
    meta:
        author = "xCEVre"
        description = "Detects DER and PEM encoded X.509 certificates"

    strings:
        $der_cert  = { 30 82 } // DER-encoded certificate
        $pem_cert  = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 43 45 52 54 49 46 49 43 41 54 45 2D 2D 2D 2D 2D } // PEM-encoded certificate

    condition:
        $der_cert at 0 or $pem_cert at 0
}

rule file_detect_magic_X509_CSR {
    meta:
        author = "xCEVre"
        description = "Detects PEM encoded X.509 Certificate Signing Request (CSR)"
        severityLevel= "INFORMATIONAL"

    strings:
        $csr = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 43 45 52 54 49 46 49 43 41 54 45 20 52 45 51 55 45 53 54 2D 2D 2D 2D 2D } // CSR request

    condition:
        $csr at 0
}


rule file_detect_magic_SSH_Public_Key {
    meta:
        author = "xCEVre"
        description = "Detects OpenSSH public key files"
        severityLevel= "INFORMATIONAL"

    strings:
        $ssh_pub = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 53 53 48 32 20 4B 45 59 2D 2D 2D 2D 2D } // SSH2 public key

    condition:
        $ssh_pub at 0
}

rule file_detect_magic_PKCS8_Private_Key {
    meta:
        author = "xCEVre"
        description = "Detects PEM encoded PKCS#8 private keys"

    strings:
        $pkcs8_key = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D } // "-----BEGIN PRIVATE KEY-----"

    condition:
        $pkcs8_key at 0
}

rule file_detect_magic_RSA_Private_Key {
    meta:
        author = "xCEVre"
        description = "Detects PEM encoded RSA private keys"

    strings:
        $rsa_key = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 52 45 41 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D } // "-----BEGIN RSA PRIVATE KEY-----"

    condition:
        $rsa_key at 0
}

rule file_detect_magic_DSA_Private_Key {
    meta:
        author = "xCEVre"
        description = "Detects PEM encoded DSA private keys"

    strings:
        $dsa_key = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 44 53 41 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D } // "-----BEGIN DSA PRIVATE KEY-----"

    condition:
        $dsa_key at 0
}

rule file_detect_magic_OpenSSH_Private_Key {
    meta:
        author = "xCEVre"
        description = "Detects OpenSSH private keys"

    strings:
        $openssh_key = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 4F 50 45 4E 53 53 48 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D } // "-----BEGIN OPENSSH PRIVATE KEY-----"

    condition:
        $openssh_key at 0
}

rule file_detect_magic_PuTTY_Private_Key_V2 {
    meta:
        author = "xCEVre"
        description = "Detects PuTTY private key file version 2"

    strings:
        $putty_v2 = { 50 75 54 54 59 2D 55 73 65 72 2D 4B 65 79 2D 46 69 6C 65 2D 32 3A } // "PuTTY-User-Key-File-2:"

    condition:
        $putty_v2 at 0
}

rule file_detect_magic_PuTTY_Private_Key_V3 {
    meta:
        author = "xCEVre"
        description = "Detects PuTTY private key file version 3"

    strings:
        $putty_v3 = { 50 75 54 54 59 2D 55 73 65 72 2D 4B 65 79 2D 46 69 6C 65 2D 33 3A } // "PuTTY-User-Key-File-3:"

    condition:
        $putty_v3 at 0
}


rule file_detect_magic_GZIP {
    meta:
        author = "xCEVre"
        description = "Detects GZIP compressed files by their magic bytes"

    strings:
        $header = { 1F 8B }

    condition:
        $header at 0
}

rule file_detect_magic_XZ {
    meta:
        author = "xCEVre"
        description = "Detects XZ compressed files by their magic bytes"
        severityLevel= "ARCHIVE"
    strings:
        $header = { FD 37 7A 58 5A 00 }

    condition:
        $header at 0
}

rule file_detect_magic_LZ4 {
    meta:
        author = "xCEVre"
        description = "Detects LZ4 compressed files by their magic bytes"
        severityLevel= "ARCHIVE"
    strings:
        $header = { 04 22 4D 18 }

    condition:
        $header at 0
}

rule file_detect_magic_CAB {
    meta:
        author = "xCEVre"
        description = "Detects Microsoft Cabinet files by their magic bytes"

    strings:
        $header = { 4D 53 43 46 }

    condition:
        $header at 0
}
rule file_detect_magic_7Z {
    meta:
        author = "xCEVre"
        description = "Detects 7-Zip archive files by their magic bytes"

    strings:
        $header = { 37 7A BC AF 27 1C } // 7z¼¯'

    condition:
        $header at 0
}

rule file_detect_magic_Matroska {
    meta:
        author = "xCEVre"
        description = "Detects Matroska media container files (MKV, MKA, MKS, MK3D, WebM)"
		severityLevel= "INFORMATIONAL"
    strings:
        $header = { 1A 45 DF A3 } // EBML заголовок Matroska

    condition:
        $header at 0
}

rule file_detect_magic_DER {
    meta:
        author = "xCEVre"
        description = "Detects DER-encoded X.509 certificates"

    strings:
        $header = { 30 82 } // ASN.1 DER-формат

    condition:
        $header at 0
}

rule file_detect_magic_WASM {
    meta:
        author = "xCEVre"
        description = "Detects WebAssembly binary files by their magic bytes"

    strings:
		//			{ 00 61 73 6D 01 00 00 00 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7F ?? ?? ?? ?? ?? ?? 7F ?? ?? ?? ?? ?? }
		$header =	{ 00 61 73 6D } // "asm" — WebAssembly magic header

    condition:
        $header at 0
}

rule file_detect_magic_LeptonJPEG {
    meta:
        author = "xCEVre"
        description = "Detects Lepton compressed JPEG images by their magic bytes"
        severityLevel= "INFORMATIONAL"

    strings:
        $header = { CF 84 01 } // Lepton JPEG magic header

    condition:
        $header at 0
}

rule file_detect_magic_RTF {
    meta:
        author = "xCEVre"
        description = "Detects Rich Text Format (RTF) files by their magic bytes"

    strings:
        $header = { 7B 5C 72 74 66 31 } // RTF header {\rtf1

    condition:
        $header at 0
}
rule file_detect_magic_GIF {
    meta:
        author = "xCEVre"
        description = "Detects GIF files by their magic bytes"
        severityLevel= "INFORMATIONAL"

    strings:
        $header = { 47 49 46 38 } // GIF8 magic bytes

    condition:
        $header at 0
}


rule file_detect_magic_ZIP{
    meta:
        author = "xCEVre"
        description = "Detects files that contain the ZIP magic number (PK..)"  // Описание правила
        date = "2025-04-01"
        severityLevel= "ARCHIVE"

    strings:
        $zip_magic = { 50 4B 03 04 }

    condition:
        $zip_magic at 0
}

rule file_detect_magic_MPEG_Program_Stream {
    meta:
        author = "xCEVre"
        description = "Detects MPEG Program Stream files (MPEG-1 Part 1 and MPEG-2 Part 1)"

    strings:
        $header_1 = { 00 00 01 BA } // MPEG Program Stream header (MPEG-1 Part 1 and MPEG-2 Part 1)

    condition:
        $header_1 at 0
}

rule file_detect_magic_MPEG_Video {
    meta:
        author = "xCEVre"
        description = "Detects MPEG-1 and MPEG-2 video files by their magic bytes"

    strings:
        $header_2 = { 00 00 01 B3 } // MPEG-1 video and MPEG-2 video header

    condition:
        $header_2 at 0
}





rule file_detect_magic_Roblox_Place {
    meta:
        author = "xCEVre"
        description = "Detects Roblox place file (rbxl) by magic bytes"

    strings:
        $header = { 3C 72 6F 62 6C 6F 78 21 } // "<roblox!"

    condition:
        $header at 0
}
rule file_detect_magic_Lua_Bytecode {
    meta:
        author = "xCEVre"
        description = "Detects Lua bytecode file (luac) by magic bytes"

    strings:
        $header = { 1B 4C 75 61 } // Lua bytecode magic number

    condition:
        $header at 0
}

rule file_detect_magic_PGP {
    meta:
        author = "xCEVre"
        description = "Detects PGP file by magic bytes"

    strings:
        $pgp_header = { 85 ?? ?? 03 } // PGP file magic bytes

    condition:
        $pgp_header at 0
}
rule file_detect_magic_Zstandard {
    meta:
        author = "xCEVre"
        description = "Detects Zstandard compressed file by magic bytes"

    strings:
        $zst_header = { 28 B5 2F FD } // Zstandard compression magic bytes

    condition:
        $zst_header at 0
}
rule file_detect_magic_QCOW {
    meta:
        author = "xCEVre"
        description = "Detects QCOW file by magic bytes"

    strings:
        $qcow_header = { 51 46 49 } // QFI

    condition:
        $qcow_header at 0
}
rule file_detect_magic_FLV {
    meta:
        author = "xCEVre"
        description = "Detects FLV (Flash Video) file by magic bytes"

    strings:
        $flv_header = { 46 4C 56 } // FLV

    condition:
        $flv_header at 0
}
rule file_detect_magic_VDI {
    meta:
        author = "xCEVre"
        description = "Detects VirtualBox Virtual Hard Disk (VDI) file by magic string"

    strings:
        $vdi_header = { 3C 3C 3C 20 4F 72 61 63 6C 65 20 56 4D 20 56 69 72 74 75 61 6C 42 6F 78 20 44 69 73 6B 20 49 6D 61 67 65 20 3E 3E 3E }

    condition:
        $vdi_header at 0
}

rule file_detect_magic_VHD {
    meta:
        author = "xCEVre"
        description = "Detects Windows Virtual PC Virtual Hard Disk (VHD) file by magic string"

    strings:
        $vhd_header = { 63 6F 6E 65 63 74 69 78 } // "conectix"

    condition:
        $vhd_header at 0
}
rule file_detect_magic_VHDX {
    meta:
        author = "xCEVre"
        description = "Detects Windows Virtual PC Windows 8 Virtual Hard Disk (VHDX) file by magic string"

    strings:
        $vhdx_header = { 76 68 64 78 66 69 6C 65 } // "vhdxfile"

    condition:
        $vhdx_header at 0
}

rule file_detect_magic_ISZ {
    meta:
        author = "xCEVre"
        description = "Detects ISZ (Compressed ISO image) file by magic string"

    strings:
        $isz_header = { 49 73 5A 21 } // "IsZ!"

    condition:
        $isz_header at 0
}

rule file_detect_magic_DAA {
    meta:
        author = "xCEVre"
        description = "Detects DAA (Direct Access Archive) file by magic string"

    strings:
        $daa_header = { 44 41 41 } // "DAA"

    condition:
        $daa_header at 0
}

rule file_detect_magic_EVT {
    meta:
        author = "xCEVre"
        description = "Detects EVT (Windows Event Viewer file) by magic string"

    strings:
        $evt_header = { 4C 66 4C 65 } // "LfLe"

    condition:
        $evt_header at 0
}

rule file_detect_magic_EVTX {
    meta:
        author = "xCEVre"
        description = "Detects EVTX (Windows Event Viewer XML file) by magic string"

    strings:
        $evtx_header = { 45 6C 66 46 69 6C 65 } // "ElfFile"

    condition:
        $evtx_header at 0
}
rule file_detect_magic_BLEND {
    meta:
        author = "xCEVre"
        description = "Detects Blender file format by magic string"

    strings:
        $blender_header = { 42 4C 45 4E 44 45 52 } // "BLENDER"

    condition:
        $blender_header at 0
}

rule file_detect_magic_JXL {
    meta:
        author = "xCEVre"
        description = "Detects JPEG XL (JXL) image format by magic string"

    strings:
        $jxl_header_1 = { 00 00 00 0C 4A 58 4C 20 0D 0A 87 0A } // First magic sequence for JXL
        $jxl_header_2 = { FF 0A } // Second magic sequence for JXL

    condition:
        ($jxl_header_1 at 0 or $jxl_header_2 at 0)
}
rule file_detect_magic_TTF {
    meta:
        author = "xCEVre"
        description = "Detects TrueType font (TTF), TrueType collection (TTC), and dfont by magic bytes"

    strings:
        $ttf_header = { FF 0A } // TrueType font magic bytes
        $ttf_header_2 = { 00 01 00 00 00 } // Alternative TTF header

    condition:
        $ttf_header at 0 or $ttf_header_2 at 0
}

rule file_detect_magic_OTF {
    meta:
        author = "xCEVre"
        description = "Detects OpenType font (OTF) by magic bytes"
        severityLevel= "INFORMATIONAL"

    strings:
        $otf_header = { 4F 54 54 4F } // "OTTO" header for OpenType font

    condition:
        $otf_header at 0
}

rule file_detect_magic_Modulefile {
    meta:
        author = "xCEVre"
        description = "Detects Modulefile for Environment Modules"

    strings:
        $modulefile_header = { 23 25 4D 6F 64 75 6C 65 } // "#%Module" for Modulefile

    condition:
        $modulefile_header at 0
}

rule file_detect_magic_VBE {
    meta:
        author = "xCEVre"
        description = "Detects VBScript Encoded script (VBE) by magic bytes"

    strings:
        $vbe_header = { 23 40 7E 5E } // "#@~^" header for VBE (VBScript Encoded script)

    condition:
        $vbe_header at 0
}

rule file_detect_magic_CDB {
    meta:
        author = "xCEVre"
        description = "Detects MikroTik WinBox Connection Database (CDB) by magic bytes"

    strings:
        $cdb_header = { 0D F0 1D C0 } // MikroTik WinBox Connection Database header

    condition:
        $cdb_header at 0
}

rule file_detect_magic_M3U {
    meta:
        author = "xCEVre"
        description = "Detects Multimedia playlist (M3U, M3U8) files by magic bytes"
        severityLevel= "INFORMATIONAL"

    strings:
        $m3u_header = { 23 45 58 54 4D 33 55 } // "#EXTM3U" header for M3U playlist files

    condition:
        $m3u_header at 0
}

rule file_detect_magic_PGP_Public_Key {
    meta:
        author = "xCEVre"
        description = "Detects Armored PGP public key by magic bytes"
        severityLevel= "INFORMATIONAL"

    strings:
        $pgp_header = { 2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 47 50 20 50 55 42 4C 49 43 20 4B 45 49 20 42 4C 4F 43 4B 2D 2D 2D 2D 2D } // "-----BEGIN PGP PUBLIC KEY BLOCK-----"

    condition:
        $pgp_header at 0
}

rule file_detect_magic_MESA_shader_CACHE_DB {
    meta:
        author = "xCEVre"
        description = "Detects mesa shader cache .{db,idx} "
        severityLevel= "INFORMATIONAL"

    strings:
        $header = { 4D 45 53 41 5F 44 42 00 } // "MESA_DB\0"

    condition:
        $header at 0
}







//rule file_detect_magic_zlib {
//    meta:
//        author = "xCEVre"
//        description = "Detects zlib compression with no compression and no preset dictionary"
//    strings:
//        $header_1 = { 78 01 } // zlib No Compression (no preset dictionary)
//        $header_2 = { 78 20 } // zlib No compression (with preset dictionary)
//        $header_3 = { 78 5E } // zlib Best speed (no preset dictionary)
//        $header_4 = { 78 7D } // zlib Best speed (with preset dictionary)
//        $header_5 = { 78 9C } // zlib Default compression (no preset dictionary)
//        $header_6 = { 78 BB } // zlib Default compression (with preset dictionary)
//        $header_7 = { 78 DA } // zlib Best compression (no preset dictionary)
//        $header_8 = { 78 F9 } // zlib Best compression (with preset dictionary)
//    condition:
//        (filesize >= 6) and (any of them at 0) and (uint32(filesize - 4) != 0)
//}

