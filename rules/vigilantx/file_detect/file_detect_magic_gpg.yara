rule vigilantx_file_detect_magic_gpg_sig {
  meta:
    description = "Detects Java class file"
    author      = "xCEVre"
    date        = "2025-04-05"

  strings:
    $begin = "-----BEGIN PGP SIGNATURE-----"
    $end   = "-----END PGP SIGNATURE-----"

  condition:
    any of them
}
