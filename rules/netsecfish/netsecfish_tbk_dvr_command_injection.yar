rule netsecfish_tbk_dvr_command_injection: EXPLOIT CVE CWE_78 {
  meta:
    author = "netsecfish"
    date   = "Apr 11, 2024"
    src    = "https://github.com/netsecfish/tbk_dvr_command_injection"
    cwe    = "CWE-78"

  strings:
    $controller = "device.rsp"
    $word_1     = "___S_O_S_T_R_E_A_MAX___"
    $word_2     = "mdb=sos"
    $word_3     = "mdc="

  condition:
    all of them
}
