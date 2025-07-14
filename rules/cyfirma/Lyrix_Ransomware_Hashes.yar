import "hash"

rule Lyrix_Ransomware_Hashes {
  meta:
    author      = "Cyfirma Research"
    description = "Detects presence of hardcoded indicators from Lyrix ransomware"
    date        = "2025-05-06"

  condition:
    hash.sha256(0, filesize) == "fcfa43ecb55ba6a46d8351257a491025022f85e9ae9d5e93d945073f612c877b" or
    hash.sha256(0, filesize) == "77706303f801496d82f83189beff412d83a362f017cadecc7a3e349a699ce458" or
    hash.md5(0, filesize) == "d298fb4197d65eabf1ef427c2eb737f1" or
    hash.md5(0, filesize) == "72a8f2c6e5628f5e8e3c4dc7dcdb93cb"

}
