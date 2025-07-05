rule vigilantx_file_detect_magic_JAVA_SER {
  meta:
    description = "Detects Java serialized object files of any version at the beginning of the file"
    author      = "xCEVre"
    date        = "2025-04-01"

  strings:
    $version_5 = { AC ED 00 05 }  // Версия 5

  condition:
    any of them at 0
}

rule vigilantx_file_detect_magic_JAVA_CLASS {
  meta:
    description = "Detects Java class file"
    author      = "xCEVre"
    date        = "2025-04-05"

  strings:
    $magic = { CA FE BA BE 00 00 00 }

  condition:
    $magic at 0
}

rule vigilantx_file_detect_magic_JAVA_CLASS_v8 {
  meta:
    description = "Detects Java 1.8 class file"
    author      = "xCEVre"
    date        = "2025-04-05"

  strings:
    $magic = { CA FE BA BE 00 00 00 34 }

  condition:
    $magic at 0
}

rule vigilantx_file_detect_magic_JAVA_CLASS_v21 {
  meta:
    description = "Detects Java 21 class file"
    author      = "xCEVre"
    date        = "2025-04-05"

  strings:
    $magic = { CA FE BA BE 00 00 00 41 }

  condition:
    $magic at 0
}

rule vigilantx_file_detect_magic_JAVA_CLASS_v23 {
  meta:
    description = "Detects Java 23 class file"
    author      = "xCEVre"
    date        = "2025-04-05"

  strings:
    $magic = { CA FE BA BE 00 00 00 43 }

  condition:
    $magic at 0
}

rule vigilantx_file_detect_magic_JAVA_CLASS_v25 {
    meta:
        description = "Detects Java 25 (JDK 25) class file format"
        author      = "xCEVre"
        date        = "2025-07-05"
    strings:
        $magic = { CA FE BA BE 00 00 00 45 }
    condition:
        $magic at 0
}

rule vigilantx_file_detect_magic_JAVA_MODULE {
  meta:
    author        = "xCEVre"
    date          = "2025-04-15"
    severityLevel = "ARCHIVE"
    description   = "Detects  'Java module image (little endian)' 'modules' files"

  strings:
    $header = { DA DA FE CA }

  condition:
    $header at 0
}

rule vigilantx_file_detect_magic_JAVA_MODULE_V1 {
  meta:
    author        = "xCEVre"
    date          = "2025-04-15"
    severityLevel = "ARCHIVE"
    description   = "Detects  'Java module image (little endian), version 1.0' 'modules' files"

  strings:
    $header = { DA DA FE CA 00 00 01 }

  condition:
    $header at 0
}
