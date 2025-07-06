rule vigilantx_data_exfiltration_discord_webhooks {
  meta:
    author = "VigilantX"

  strings:
    $link_1 = "discord.com/api/webhooks"
    $link_2 = "discohook.org/api/webhooks"

  condition:
    any of them
}

