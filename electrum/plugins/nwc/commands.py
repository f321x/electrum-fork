from electrum.commands import plugin_command
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .nwcserver import NWCServerPlugin
    from electrum.commands import Commands

plugin_name = "nwc"

@plugin_command('', plugin_name)
async def add_connection(self: 'Commands', budget_sat_24h: int, valid_for_seconds: int, plugin=None) -> dict:
    try:
        connection_string: str = plugin.create_connection(budget_sat_24h, valid_for_seconds)
    except Exception as e:
        return {'error': str(e)}
    # rather raise instead of returning an error
    return {'connection_string': connection_string}

@plugin_command('', plugin_name)
async def remove_connection(self: 'Commands', uri_or_pubkey: str, plugin=None) -> dict:
    """Either provide the whole connection string or just the pubkey (before the @) to remove"""
    if len(uri_or_pubkey) < 64:
        return {'error': 'invalid pubkey or connection string'}
    try:
        plugin.remove_connection(uri_or_pubkey)
    except KeyError:
        return {uri_or_pubkey: "not_found"}
    return {uri_or_pubkey: "removed"}

@plugin_command('', plugin_name)
async def list_connections(self: 'Commands', plugin=None) -> dict:
    """List all connections"""
    connections: dict = plugin.list_connections()
    return connections or {'none': 'none'}


