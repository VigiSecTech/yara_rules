import "hash"

rule ELF_Chaos_RAT {
  meta:
    description = "Detects Linux ELF binaries <10MB with indicators of CHAOS-RAT-generated payloads"

    author = "Acronis TRU"

    date = "2025-04-16"

  strings:
    $chaos    = "tiagorlampert/CHAOS" ascii
    $library1 = "BurntSushi/xgb" ascii
    $library2 = "gen2brain/shm" ascii
    $library3 = "kbinani/screenshot" ascii

  condition:
    uint32(0) == 0x464c457f and  // ELF magic number in little-endian     
    filesize < 10MB and

    $chaos and

    2 of ($library*)
}

rule ELF_Chaos_RAT_SHA256 {
  meta:
    description = "Detects Linux ELF binaries <10MB with indicators of CHAOS-RAT-generated payloads"
    author      = "Acronis TRU"
    date        = "2025-04-16"

  condition:
    hash.sha256(0, filesize) == "1e074d9dca6ef0edd24afb2d13ca4429def5fc5486cd4170c989ef60efd0bbb0" or
    hash.sha256(0, filesize) == "d0a63e059ed2c921c37c83246cdf4de0c8bc462b7c1d4b4ecd23a24196be7dd7" or
    hash.sha256(0, filesize) == "773c935a13ab49cc4613b30e8d2a75f1bde3b85b0bba6303eab756d70f459693" or
    hash.sha256(0, filesize) == "c8dc86afd1cd46534f4f9869efaa3b6b9b9a1efaf3c259bb87000702807f5844" or
    hash.sha256(0, filesize) == "90c8b7f89c8a23b7a056df8fd190263ca91fe4e27bda174a9c268adbfc5c0f04" or
    hash.sha256(0, filesize) == "8c0606db237cfa33fa3fb99a56072063177b61fa2c8873ed6af712bba2dc56d9" or
    hash.sha256(0, filesize) == "2732fc2bb7b6413c899b6ac1608818e4ee9f0e5f1d14e32c9c29982eecd50f87" or
    hash.sha256(0, filesize) == "839b3a46abee1b234c4f69acd554e494c861dcc533bb79bd0d15b9855ae1bed7" or
    hash.sha256(0, filesize) == "77962a384d251f0aa8e3008a88f206d6cb1f7401c759c4614e3bfe865e3e985c" or
    hash.sha256(0, filesize) == "57f825a556330e94d12475f21c2245fa1ee15aedd61bffb55587b54e970f1aad" or
    hash.sha256(0, filesize) == "44c54d9d0b8d4862ad7424c677a6645edb711a6d0f36d6e87d7bae7a2cb14d68" or
    hash.sha256(0, filesize) == "c9694483c9fc15b2649359dfbd8322f0f6dd7a0a7da75499e03dbc4de2b23cad" or
    hash.sha256(0, filesize) == "080f56cea7acfd9c20fc931e53ea1225eb6b00cf2f05a76943e6cf0770504c64" or
    hash.sha256(0, filesize) == "a583bdf46f901364ed8e60f6aadd2b31be12a27ffccecc962872bc73a9ffd46c" or
    hash.sha256(0, filesize) == "a364ec51aa9314f831bc498ddaf82738766ca83b51401f77dbd857ba4e32a53b" or
    hash.sha256(0, filesize) == "a6307aad70195369e7ca5575f1ab81c2fd82de2fe561179e38933f9da28c4850" or
    hash.sha256(0, filesize) == "c39184aeb42616d7bf6daaddb9792549eb354076b4559e5d85392ade2e41763e" or
    hash.sha256(0, filesize) == "67534c144a7373cacbd8f9bd9585a2b74ddbb03c2c0721241d65c62726984a0a" or
    hash.sha256(0, filesize) == "a51416ea472658b5530a92163e64cfa51f983dfabe3da38e0646e92fb14de191" or  // https://cyberpress.org/new-chaos-rat-affects-linux-and-windows-users/
    hash.sha256(0, filesize) == "719082b1e5c0d18cc0283e537215b53a864857ac936a0c7d3ddbaf7c7944cf79"
}
