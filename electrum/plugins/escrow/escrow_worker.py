import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional
from abc import ABC, abstractmethod
from concurrent.futures import Future, CancelledError

from electrum.util import get_asyncio_loop
from electrum.logging import Logger

if TYPE_CHECKING:
    from .nostr_worker import EscrowNostrWorker
    from electrum.wallet import Abstract_Wallet


@dataclass(frozen=True)
class EscrowAgentProfile:
    """
    Information broadcast by the escrow agent, visible to its customers.
    Using Nostr kind 0 (NIP-01) profile event.
    """
    name: str
    about: str  # short description
    languages: list[str]
    service_fee_ppm: int  # fees of traded amount (excluding bonds) in ppm
    gpg_fingerprint: Optional[str] = None
    picture: Optional[str] = None  # url to profile picture
    website: Optional[str] = None


class EscrowWorker(ABC, Logger):
    NOSTR_PROTOCOL_VERSION = 1

    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict):
        Logger.__init__(self)
        self.wallet = wallet
        self.nostr_worker = nostr_worker
        self.storage = storage
        self.main_task = None  # type: Optional[Future]

    @abstractmethod
    async def main_loop(self):
        pass

    @classmethod
    def create(cls, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict) -> 'EscrowWorker':
        worker = cls(wallet, nostr_worker, storage)
        task = asyncio.run_coroutine_threadsafe(
            worker.main_loop(),
            get_asyncio_loop(),
        )

        def done_callback(f):
            try:
                f.result()
            except (asyncio.CancelledError, CancelledError):
                pass
            except Exception:
                worker.logger.exception("EscrowWorker task failed")

        task.add_done_callback(done_callback)
        worker.main_task = task
        return worker

    def stop(self):
        self.logger.debug(f"escrow worker stopped")
        if self.main_task:
            self.main_task.cancel()
            self.main_task = None
