rule vigilantx_potentially_dangerous_java_socket {
  meta:
    description = "Обнаруживает использование java.net.Socket для установления сетевых соединений"
    author      = "VigilantX"

  strings:
    $socket_class = "java/net/Socket" fullword ascii

  condition:
    vigilantx_file_detect_magic_JAVA_CLASS and all of them
}
