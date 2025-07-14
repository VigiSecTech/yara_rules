import "hash"

rule DuplexSPY_RAT {
  meta:
    description = "Detects DuplexSPY_RAT based on hashes "
    author      = "CYFIRMA"
    date        = "2025-05-06"

  condition:
    hash.sha256(0, filesize) == "2c1abd6bc9facae420235e5776b3eeaa3fc79514cf033307f648313362b8b721" or
    hash.sha256(0, filesize) == "ab036cc442800d2d71a3baa9f2d6b27e3813b9f740d7c3e7635b84e3e7a8d66a"
}
