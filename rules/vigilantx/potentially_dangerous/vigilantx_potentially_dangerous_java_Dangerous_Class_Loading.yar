rule vigilantx_potentially_dangerous_java_Dangerous_Class_Loading {
  meta:
    author      = "VigilantX"
    description = "Detects usage of Class.forName() for dynamic class loading"

  strings:
    $class_for_name = /Class\.forName\s*\(/ nocase ascii wide

  condition:
    vigilantx_file_detect_magic_JAVA_CLASS and all of them
}
