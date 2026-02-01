# Icon attribution (Flaticon License):
# The icon trust_icon.png has been designed using resources from Flaticon.com by the author gravisio.

from electrum.simple_config import SimpleConfig, ConfigVar

plugin_name = "authenticity_tool"

# minimum amount of valid signatures required to consider a file valid
SimpleConfig.AUTHENTICITY_TOOL_MIN_SIGS = ConfigVar(
    key='plugins.authenticity_tool.min_sigs',
    default=2,
    type_=int,
    plugin=plugin_name
)
