import "hash"

rule APT36_IOCs_Indicators {
  meta:
    author       = "Cyfirma Research"
    description  = "Detects known APT36-related indicators (hashes, IP, domains)"
    date         = "2025-06-08"
    threat_group = "APT36 / Transparent Tribe"

  strings:
    // Domains used by APT36
    $domain1  = "SuperPrimeServices.com"
    $domain2  = "Advising-Receipts.com"
    $domain3  = "FunDay24.ru"
    $domain4  = "slotgacorterbaru.xyz"
    $domain5  = "servisyeni.xyz"
    $domain6  = "chillchad.xyz"
    $domain7  = "ggpoker.xyz"
    $domain8  = "boldcatchpoint.shop"
    $domain9  = "zhangthird.shop"
    $domain10 = "vipwin.buzz"
    $domain11 = "wholly-well.info"
    $domain12 = "rapio.site"
    $domain13 = "55cc.info"
    $domain14 = "megasofteware.net"
    $domain15 = "worrr19.sbs"
    $domain16 = "kp85.cyou"
    $domain17 = "mczacji.top"
    $domain18 = "59292406.xyz"

    // IPs used by APT36
    $ip1  = "76.223.54.146"
    $ip2  = "188.114.97.7"
    $ip3  = "13.248.169.48"
    $ip4  = "84.32.84.32"
    $ip5  = "217.114.10.11"
    $ip6  = "207.244.126.106"
    $ip7  = "172.67.148.140"
    $ip8  = "198.252.111.31"
    $ip9  = "15.197.148.33"
    $ip10 = "162.254.38.217"
    $ip11 = "104.21.41.144"

  condition:
    hash.sha256(0, filesize) == "f03ac870cb91c00b51ddf29b6028d9ddf42477970eafa7c556e3a3d74ada25c9" or
    hash.sha256(0, filesize) == "55b7e20e42b57a32db29ea3f65d0fd2b2858aaeb9307b0ebbcdad1b0fcfd8059" or
    hash.sha256(0, filesize) == "55972edf001fd5afb1045bd96da835841c39fec4e3d47643e6a5dd793c904332" or

    any of ($domain*) or any of ($ip*)
}
