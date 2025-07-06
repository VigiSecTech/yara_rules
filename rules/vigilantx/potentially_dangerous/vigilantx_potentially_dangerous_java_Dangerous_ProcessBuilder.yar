rule vigilantx_potentially_dangerous_java_ProcessBuilder {
  meta:
    description = "Обнаруживает создание экземпляра ProcessBuilder в Java-классах"
    author      = "VigilantX"

  strings:
    $process_builder_class       = "java/lang/ProcessBuilder" fullword ascii
    $process_builder_constructor = "<init>" fullword ascii
    $start_method                = "start" fullword ascii

  condition:
    vigilantx_file_detect_magic_JAVA_CLASS and all of them
}
