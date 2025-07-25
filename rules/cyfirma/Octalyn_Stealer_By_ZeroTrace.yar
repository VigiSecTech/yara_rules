rule Octalyn_Stealer_By_ZeroTrace {
  meta:
    description    = "Detects Octalyn Stealer on Github"
    author         = "Cyfirma Research"
    malware_family = "Octalyn Stealer"
    date           = "2025-07-11"

  strings:
    $name1 = "Octalyn" wide
    $name2 = "steffz" wide
    $h1    = "3b3a096a9c507529919f92154f682490fa8e135f3460549a917cf23113a7b828"
    $h2    = "8bd9925f7b7663ca2fcb305870248bd5de0c684342c364c24ef24bffbcdecd8b"
    $h3    = "8bb868a4bd9ed5e540c3d6717b0baa1cd831fc520ee02889bc55e2aac66d9d34"
    $h4    = "cea94fd48ef98f6e9db120cdb33fa1099846ebcf9e6d6f8de3b53250d2087f0a"
    $h5    = "8af7fc21bc9c13d877f598886f363a4c7c1105bcda18e17db74d7e1584a9cae2"
    $h6    = "abe96669d90f52529b5dad847f43961a4b8b56c3893f6233a404b688c5a6069e"
    $h7    = "44778cf0de10af616ef2d8a5cc5048f7cf0faa204563eab590a1a9ea4a168ef7"

  condition:
    any of ($name*) or any of ($h*)
}
