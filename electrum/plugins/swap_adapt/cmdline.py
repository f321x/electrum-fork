from .swap_adapt import SwapAdaptPlugin
from electrum.plugin import hook

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.daemon import Daemon

class Plugin(SwapAdaptPlugin):
    def __init__(self, *args):
        SwapAdaptPlugin.__init__(self, *args)

    @hook
    def daemon_wallet_loaded(self, daemon: 'Daemon', wallet: 'Abstract_Wallet'):
        self.logger.debug(f"swapadapt plugin daemon_wallet_loaded called")
        self.start_plugin(wallet)

    @hook
    def close_wallet(self, *args, **kwargs):
        self.stop_plugin()

