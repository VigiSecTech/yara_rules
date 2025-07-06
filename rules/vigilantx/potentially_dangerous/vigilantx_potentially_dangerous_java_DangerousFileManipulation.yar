rule vigilantx_potentially_dangerous_java_FileOutputStream {
  meta:
    author      = "VigilantX"
  strings:
    $class = "java/io/FileOutputStream" fullword ascii
  condition:
    vigilantx_file_detect_magic_JAVA_CLASS and all of them
}
