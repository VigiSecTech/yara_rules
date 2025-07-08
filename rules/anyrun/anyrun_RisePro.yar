rule RisePro : MALWARE {
  meta:
    author      = "ANY.RUN"
    description = "Detects RisePro (stealer version)"
    date        = "2023-11-27"
    reference   = "https://any.run/cybersecurity-blog/risepro-malware-communication-analysis/"

  strings:
    $ = "t.me/RiseProSUPPORT"

  condition:
    any of them
}
