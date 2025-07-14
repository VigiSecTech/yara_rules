import "hash"

rule GhostSpy_Detection {
  meta:
    description = "Detects GhostSpy based on APK hashes, package names, IPs, and URLs"
    author      = "Cyfirma Research"
    date        = "2025-05-19"

  strings:
    // Package Name
    $package_name = "com.support.litework"

    // IP Address
    $ip1 = "37.60.233.14"

    // URLs
    $url1 = "https://stealth.gstpainel.fun"
    $url2 = "https://gsttrust.org"

  condition:
    hash.sha256(0, filesize) == "e9f2f6e47e071ed2a0df5c75e787b2512ba8a601e55c91ab49ea837fd7a0fc85" or  //apk
    hash.sha256(0, filesize) == "73e647287408b2d40f53791b8a387a2f7eb6b1bba1926276e032bf2833354cc4" or  //apk

    $package_name or
    $ip1 or
    any of ($url*)
}
