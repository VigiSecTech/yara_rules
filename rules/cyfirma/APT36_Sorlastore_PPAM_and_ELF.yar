import "hash"

rule APT36_Sorlastore_PPAM_and_ELF {
  meta:
    description  = "Detects APT36 campaign artifacts: slide.pptx, BOSS.elf, govin.sorlastore domain activity"
    author       = "CYFIRMA Researcher"
    date         = "2025-07-03"
    threat_actor = "APT36 / Transparent Tribe"

  strings:
    // URLs
    $dom1 = "sorlastore.com"
    $ip1  = "101.99.92.182"
    $ip2  = "169.254.169.254"
    $dom2 = "onthewifi.com"

  condition:
    hash.sha256(0, filesize) == "608fff2cd4b727799be762b95d497059a202991eb3401a55438071421b9b5e7a" or
    hash.sha256(0, filesize) == "ace379265be7f848d512b27d6ca95e43cef46a81dc15d1ad92ec6f494eed42ab" or
    hash.sha256(0, filesize) == "e528799a29e9048c1e71b78223311cad2699d035a731d1a6664fc8ddd0642064" or
    hash.sha256(0, filesize) == "167b387005d6d2a55ad282273c58d1786a2ee0fa3e7e0cb361d4d61d8618ee5f" or
    any of ($dom*) or
    any of ($ip*)
}
