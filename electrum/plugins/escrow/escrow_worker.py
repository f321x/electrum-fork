import asyncio
from typing import TYPE_CHECKING, Optional
from abc import ABC, abstractmethod
from concurrent.futures import Future

from electrum.util import get_asyncio_loop
from electrum.logging import Logger

if TYPE_CHECKING:
    from .nostr_worker import EscrowNostrWorker
    from electrum.wallet import Abstract_Wallet


class EscrowWorker(ABC, Logger):
    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker'):
        Logger.__init__(self)
        self.wallet = wallet
        self.nostr_worker = nostr_worker
        self.main_task = None  # type: Optional[Future]

    @abstractmethod
    async def main_loop(self):
        pass

    @classmethod
    def create(cls, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker') -> 'EscrowWorker':
        worker = cls(wallet, nostr_worker)
        task = asyncio.run_coroutine_threadsafe(
            worker.main_loop(),
            get_asyncio_loop(),
        )
        worker.main_task = task
        return worker

    def stop(self):
        self.logger.debug(f"escrow worker stopped")
        if self.main_task:
            self.main_task.cancel()
            self.main_task = None
