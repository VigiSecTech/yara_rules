rule vigilantx_potentially_dangerous_java_Reflection {
  meta:
    description = "Обнаруживает использование рефлексии для вызова методов в Java-классах"
    author      = "VigilantX"

  strings:
    $reflect_Method = "java/lang/reflect/Method" fullword ascii

  condition:
    vigilantx_file_detect_magic_JAVA_CLASS and all of them
}
