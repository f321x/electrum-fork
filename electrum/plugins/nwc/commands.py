from electrum.commands import plugin_command
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from electrum.commands import Commands

@plugin_command('', 'nwc')
async def plugin_nwc_command(self):
    return {'test': 'successfully'}
