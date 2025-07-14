import "hash"

rule Gunra_Ransomware {
  meta:
    description = "Detects Gunra Ransomware specific file hash"
    author      = "CYFIRMA Research"
    date        = "2025-05-02"

  condition:
    hash.sha256(0, filesize) == "854e5f77f788bbbe6e224195e115c749172cd12302afca370d4f9e3d53d005fd" or
    hash.md5(0, filesize) == "9a7c0adedc4c68760e49274700218507"

}
