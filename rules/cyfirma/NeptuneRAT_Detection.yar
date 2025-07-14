import "hash"

rule NeptuneRAT_Detection {
  meta:
    description  = "Detects Neptune RAT associated with FreeMasonry developer group and files hashed SHA256"
    author       = "Cyfirma Research"
    date         = "2025-03-31"
    threat_actor = "Neptune RAT (FreeMasonry Group)"
    mal_type     = "Remote Access Trojan"

  strings:
    // Developer group detection using specific keywords
    $dev_group = "FreeMasonry" wide ascii

    // RAT name detection
    $rat_name = "NeptuneRat" wide ascii

  condition:
    (
      hash.sha256(0, filesize) == "8df1065d03a97cc214e2d78cf9264a73e00012b972f4b35a85c090855d71c3a5" or  // exe
      hash.sha256(0, filesize) == "9fe8a026b5f41a4d434bb808273b83a364a1994a60e2ab7e232a31bf2b76a33f" or  // exe
      hash.sha256(0, filesize) == "e03f6f8d0ce9abdda3e3fff801babcd4448a567f330c4cac498fec39652f3c77" or  // exe

      hash.sha256(0, filesize) == "21c832f9d76b8ae74320b8fac811a761f09f871ee32c9ab1c8fb1492b95a7d04" or  // bat

      hash.sha256(0, filesize) == "e8c8f74ae15e7d809d9013bdfa2a10dd54e00d4ea5ff4ed6cd4a163b80d2d318" or  // DLL
      hash.sha256(0, filesize) == "14e196e089014313c9fa8c86ce8cffb1c7adacd7d1df7373d97b30d31b965df9" or  // DLL
      hash.sha256(0, filesize) == "add3e9a1c6654d1ec9b7fd0ffea6bdcd0eb7b3e4afa70c6776835cc238e8f179" or  // DLL
      hash.sha256(0, filesize) == "add3e9a1c6654d1ec9b7fd0ffea6bdcd0eb7b3e4afa70c6776835cc238e8f179" or  // DLL
      hash.sha256(0, filesize) == "dec534ab858a71575a3836b96d0f96df89eb8ba50f9bc69350faa0f7bcccfd25" or  // DLL
      hash.sha256(0, filesize) == "88cc579613730f847f72e28b4e880bd8104edf6d6ab37ffa0d18f273889d1a40" or  // DLL
      hash.sha256(0, filesize) == "e310a1b264912ae886cd956abc42dee846455a99f67c3ea8336a202240bd7dfa" or  // DLL
      hash.sha256(0, filesize) == "2b4aa36247da1af1de0091e7444fbf8f829d133743bb3b931618c66bbd10d10b" or  // DLL
      hash.sha256(0, filesize) == "9a35113e1d9412701d85b5af01b4ad2b1e584c6e0963e439053808b29b4da90a" or  // DLL
      hash.sha256(0, filesize) == "684d2d50dd42e7ba4e9bd595e9b6f77eb850185556c71db4eda6f78478a5e6fb" or  // DLL
      hash.sha256(0, filesize) == "9ca70da0ea94b3bea68c9a3259ec60192c5be1ae7630a08924053168bbf41335" or  // DLL
      hash.sha256(0, filesize) == "d0c6f5d916933a1f8d852ca42163ff50bfe07132fcacac03db7d20f573284208" or  // DLL
      hash.sha256(0, filesize) == "1bbd4262c8821a0290fe40a8e374c6e5fa2084331670ede42e995d3d5902efcd" or  // DLL
      hash.sha256(0, filesize) == "a19ef7ace3118ff9e5be24b388aff3e56a5bac0d4069bf8480721e3f4508706a" or  // DLL
      hash.sha256(0, filesize) == "20c31ac326b5c6076f9b1497f98b14a0acd36ff562dfa2076589a47a41d0e078" or  // DLL
      hash.sha256(0, filesize) == "6d02eb3349046034cf05e25e28ef173c01d9e0ea1f4d96530defe9e2a3d5e8a0" or  // DLL
      hash.sha256(0, filesize) == "62fdc4b159ad1b4225098276e6f2dcf29d49d9545ac9575d4ff1f6b4f00cdb65" or  // DLL
      hash.sha256(0, filesize) == "70554db8312c03c8cce38925db900cdbe8e57e88da29b0bf2f61ed1bbcaa03bd" or  // DLL
      hash.sha256(0, filesize) == "cd2b320433843d4d694ae8185c7ef07a90d7dce6d05a38ac4481ad2eab9bcfe5" or  // DLL
      hash.sha256(0, filesize) == "630b1879c2e09b2f49dd703a951fb3786ede36b79c5f00b813e6cb99462bf07c"  // DLL
    )

    or ($dev_group or $rat_name)
}
