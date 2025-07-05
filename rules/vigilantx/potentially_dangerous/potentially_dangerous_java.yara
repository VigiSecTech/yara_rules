rule vigilantx_potentially_dangerous_java_Runtime_cmd {
  meta:
    author        = "xCEVre"
    date          = "2025-07-05"
    severityLevel = "UNKNOWN"
    description   = "Detects '.rpyc' files"
  strings:
    $runtime = "java/lang/Runtime"
    $get = "getRuntime"
    $exec = "exec"
  condition:
    vigilantx_file_detect_magic_JAVA_CLASS and all of them
}
