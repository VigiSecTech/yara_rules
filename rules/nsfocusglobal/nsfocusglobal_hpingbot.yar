rule nsfocusglobal_hpingbot {
  meta:
    author      = "nsfocusglobal.com"
    description = "A New Botnet Family Based on Pastebin Payload Delivery Chain and Hping3 DDoS Module "
    date        = "2025-07-03"
    reference   = "https://nsfocusglobal.com/hpingbot-a-new-botnet-family-based-on-pastebin-payload-delivery-chain-and-hping3-ddos-module/"

  strings:
    $ip_1 = "45.139.113.61"
    $ip_2 = "193.32.162.210"
    $ip_3 = "128.0.118.18"
    $ip_4 = "93.123.118.21"
    $ip_5 = "94.156.181.41"

  condition:
    any of them
}

