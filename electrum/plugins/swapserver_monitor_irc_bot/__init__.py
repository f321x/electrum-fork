from electrum.simple_config import SimpleConfig, ConfigVar

SimpleConfig.SAMPLE_DURATION = ConfigVar('plugins.swapserver_monitor_irc_bot.sample_duration', default=86400, type_=int, plugin=__name__)
SimpleConfig.UTC_24H_PUBLICATION_TIME = ConfigVar('plugins.swapserver_monitor_irc_bot.utc_24h_publication_time', default=16, type_=int, plugin=__name__)
SimpleConfig.SWAP_MONITOR_IRC_USERNAME = ConfigVar('plugins.swapserver_monitor_irc_bot.irc_username', default="swapsm", type_=str, plugin=__name__)
SimpleConfig.SWAP_MONITOR_IRC_CHANNEL = ConfigVar('plugins.swapserver_monitor_irc_bot.irc_channel', default="#electrum", type_=str, plugin=__name__)
SimpleConfig.SWAP_MONITOR_IRC_SERVER = ConfigVar('plugins.swapserver_monitor_irc_bot.irc_server', default="irc.libera.chat:6697", type_=str, plugin=__name__)
