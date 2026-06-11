from typing import Optional, TYPE_CHECKING, Dict, Type
from enum import Enum

from electrum.i18n import _
from electrum.plugin import BasePlugin, hook
from electrum.util import UserFacingException

from .nostr_worker import EscrowNostrWorker
from .agent import EscrowAgent
from .client import EscrowClient

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet
    from electrum.daemon import Daemon
    from .escrow_worker import EscrowWorker


class StoragePurpose(Enum):
    AGENT_DATA = 'agent_data'
    CLIENT_DATA = 'client_data'


class EscrowPlugin(BasePlugin):
    ICON_FILE_NAME = "escrow-icon.png"
    # todo: check compatibility with electrum version
    # todo: check for plugin updates (nostr)
    # todo: telegram bot notification
    # todo: onchain support (with taproot)
    # todo: verifiable 'first seen' with OTS

    def __init__(self, parent, config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallets: Dict['Abstract_Wallet', 'EscrowWorker'] = {}
        self.config = config
        self.nostr_worker: Optional[EscrowNostrWorker] = None
        self.logger.debug("Escrow plugin created")

    def is_available(self) -> bool:
        network_available = not self.config.NETWORK_OFFLINE
        if not network_available:
            self.logger.warning("Escrow Plugin unavailable: no network")
        return network_available

    @hook
    def daemon_wallet_loaded(self, _daemon: 'Daemon', wallet: 'Abstract_Wallet'):
        self._load_wallet(wallet)

    def _load_wallet(self, wallet: 'Abstract_Wallet'):
        if wallet in self.wallets:
            return  # already loaded

        if wallet.network is None:
            self.logger.warning("not loading wallet, no network available")
            return

        if not self.nostr_worker:
            # create shared nostr worker for all wallets
            self.nostr_worker = EscrowNostrWorker(self.config, wallet.network)
            self.nostr_worker.start()

        if self.is_escrow_agent(wallet) and wallet.has_lightning():
            worker = EscrowAgent.create(
                wallet,
                self.nostr_worker,
                self._get_storage(wallet=wallet, purpose=StoragePurpose.AGENT_DATA),
            )
        else:
            if self.is_escrow_agent(wallet):
                self.logger.warning("wallet is flagged as escrow agent but has no "
                                    "lightning support, falling back to client mode")
            worker = EscrowClient.create(
                wallet,
                self.nostr_worker,
                self._get_storage(wallet=wallet, purpose=StoragePurpose.CLIENT_DATA),
            )
        self.wallets[wallet] = worker

    @hook
    def close_wallet(self, wallet: 'Abstract_Wallet'):
        if wallet in self.wallets:
            self.wallets[wallet].stop()
            del self.wallets[wallet]

        if not self.wallets:
            # stop nostr worker if there is no open wallet left
            if self.nostr_worker:
                self.nostr_worker.stop()
                self.nostr_worker = None

    def on_close(self):
        """Called when the plugin gets disabled."""
        for worker in self.wallets.values():
            worker.stop()
        self.wallets.clear()
        if self.nostr_worker:
            self.nostr_worker.stop()
            self.nostr_worker = None

    def is_escrow_agent(self, wallet: 'Abstract_Wallet') -> bool:
        """Is stored in wallet db as the user might be agent in one wallet and user in another wallet"""
        storage = self.get_storage(wallet)
        return bool(storage.get('is_escrow_agent', False))

    def has_agent_worker(self, wallet: 'Abstract_Wallet') -> bool:
        """Whether the wallet actually runs as escrow agent. May differ from is_escrow_agent
        e.g. when the wallet is flagged as agent but has no lightning support."""
        return isinstance(self.wallets.get(wallet), EscrowAgent)

    def set_escrow_agent_mode(self, *, enabled: bool, wallet: 'Abstract_Wallet'):
        if enabled and not wallet.has_lightning():
            raise UserFacingException(
                _("Acting as escrow agent requires a wallet with Lightning support."))
        if wallet not in self.wallets:
            raise UserFacingException(_("Wallet is not loaded in the escrow plugin."))
        storage = self.get_storage(wallet)
        self.wallets[wallet].stop()
        storage['is_escrow_agent'] = enabled
        wallet.save_db()
        if enabled:
            self.wallets[wallet] = EscrowAgent.create(
                wallet,
                self.nostr_worker,
                self._get_storage(wallet=wallet, purpose=StoragePurpose.AGENT_DATA),
            )
        else:
            self.wallets[wallet] = EscrowClient.create(
                wallet,
                self.nostr_worker,
                self._get_storage(wallet=wallet, purpose=StoragePurpose.CLIENT_DATA),
            )
        self.logger.debug(f"escrow agent mode {enabled=}")

    def _get_storage(self, *, wallet: 'Abstract_Wallet', purpose: StoragePurpose) -> dict:
        storage = self.get_storage(wallet)
        key = purpose.value
        if key not in storage:
            storage[key] = {}
        return storage[key]

    def get_escrow_worker(
        self,
        wallet: 'Abstract_Wallet',
        *,
        worker_type: Type[EscrowClient | EscrowAgent]
    ) -> 'EscrowClient | EscrowAgent':
        worker = self.wallets[wallet]
        assert isinstance(worker, worker_type)
        return worker
