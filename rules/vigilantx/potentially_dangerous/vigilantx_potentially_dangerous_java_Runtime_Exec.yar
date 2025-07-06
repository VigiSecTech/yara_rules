rule vigilantx_potentially_dangerous_java_Runtime_Exec {
  meta:
    description   = "Обнаруживает потенциальные опасные вызовы Runtime.exec в Java-классах Minecraft-сервера"
    author        = "VigilantX"
    date          = "2025-07-05"
    severityLevel = "POTENTIALLY_DANGEROUS"

  strings:
    $runtime_class = "java/lang/Runtime" fullword ascii
    $get_runtime   = "getRuntime" fullword ascii
    $exec_method   = "exec" fullword ascii

  condition:
    vigilantx_file_detect_magic_JAVA_CLASS and all of them
}
