import asyncio
from typing import Optional, TYPE_CHECKING, List

import aiohttp

from electrum.plugin import BasePlugin
from electrum.network import Network
from electrum.util import get_asyncio_loop, log_exceptions, OldTaskGroup, EventListener, make_aiohttp_session

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.plugin import Plugins
    from electrum.simple_config import SimpleConfig


class SwapAdaptPlugin(BasePlugin):

    def __init__(self, parent: 'Plugins', config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.is_initialized = False
        self.wallet = None  # type: Optional['Abstract_Wallet']
        self.parent = parent
        self.config = config
        self.storage = None  # type: Optional[dict]
        self.main_task = None  # type: Optional['asyncio.Task']
        self.seen_swaps = set()  # type: set[str]
        self.startup_blockheight = None  # type: Optional[int]
        self.logger.debug(f"SwapAdaptPlugin instantiated, waiting for wallet to load...")

    def start_plugin(self, wallet: 'Abstract_Wallet'):
        if self.is_initialized:
            self.logger.debug(f"swapadapt plugin already initialized, skipping start_plugin")
            return
        self.logger.debug(f"swapadapt plugin start_plugin called")
        self.is_initialized = True
        self.wallet = wallet
        self.storage = self.get_storage(wallet)
        self.main_task = asyncio.run_coroutine_threadsafe(
            self.main_loop(),
            get_asyncio_loop(),
        )

    def stop_plugin(self):
        self.logger.debug(f"swapadapt plugin stop_plugin")
        if self.main_task:
            self.main_task.cancel()
            self.main_task = None
        self.is_initialized = False
        self.wallet = None

    @log_exceptions
    async def main_loop(self):
        while not self.wallet.network.is_connected():
            self.logger.debug(f"wallet not connected, waiting for connection")
            await asyncio.sleep(10)
        async with OldTaskGroup() as group:
            await group.spawn(self._telegram_notifier())

    async def _telegram_notifier(self):
        self.logger.debug(f"starting telegram notifier")
        local_height = self.wallet.adb.get_local_height()
        try:
            await self.send_telegram_notification(f"SwapAdapt plugin started. Local height: {local_height}")
        except aiohttp.ClientResponseError:
            self.logger.exception("")
        while True:
            await asyncio.sleep(30)
            if not self.storage or 'telegram' not in self.storage:
                continue
            if not self.wallet.lnworker or not self.wallet.lnworker.swap_manager:
                continue
            swap_messages: List[str] = []
            for swap in list(self.wallet.lnworker.swap_manager._swaps.values()):
                if swap.payment_hash in self.seen_swaps:
                    continue
                self.seen_swaps.add(swap.payment_hash)
                if swap.locktime < local_height:
                    continue  # old swap
                swap_messages.append(f"{str(swap)}")
            if swap_messages:
                try:
                    await self.send_telegram_notification('\n\n'.join(swap_messages))
                except aiohttp.ClientResponseError as e:
                    self.logger.error(f"Failed to send telegram notification: {str(e)}")

    async def send_telegram_notification(self, message: str) -> None:
        if not self.storage or 'telegram' not in self.storage:
            return
        telegram_data = self.storage['telegram']
        bot_token = telegram_data.get('bot_token')
        chat_id = telegram_data.get('chat_id')
        if not bot_token or not chat_id:
            self.logger.warning(f"Inconsistent telegram configuration: {telegram_data=}")
            del self.storage['telegram']
            return

        url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
        data = {'chat_id': chat_id, 'text': message}
        network = Network.get_instance()
        proxy = network.proxy if network else None
        async with make_aiohttp_session(proxy) as session:
            async with session.post(url, data=data, raise_for_status=True) as response:
                # set content_type to None to disable checking MIME type
                res = await response.text()
                self.logger.debug(f"telegram response: {res[:20]=}")
