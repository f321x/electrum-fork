import threading
from typing import Optional, TYPE_CHECKING, Dict, Type
from enum import Enum
from functools import partial

from electrum.i18n import _
from electrum.plugin import BasePlugin, hook
from electrum.util import UserFacingException, trigger_callback

from .nostr_worker import EscrowNostrWorker
from .agent import EscrowAgent
from .client import EscrowClient
from .backup import NostrStateBackup

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
        self.backups: Dict['Abstract_Wallet', NostrStateBackup] = {}
        # guards the worker dicts: they are mutated from the GUI thread (agent mode
        # toggle, wallet close) and from the asyncio thread (backup restore)
        self._workers_lock = threading.RLock()
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
        with self._workers_lock:
            if wallet in self.wallets:
                return  # already loaded

            if wallet.network is None:
                self.logger.warning("not loading wallet, no network available")
                return

            if not self.nostr_worker:
                # create shared nostr worker for all wallets
                self.nostr_worker = EscrowNostrWorker(self.config, wallet.network)
                self.nostr_worker.start()

            self.wallets[wallet] = self._create_trade_worker(wallet)
            if wallet.has_lightning():
                self.backups[wallet] = NostrStateBackup.create(
                    wallet,
                    self.nostr_worker,
                    self.get_storage(wallet),
                    on_state_restored=partial(self._on_backup_restored, wallet),
                )

    def _create_trade_worker(self, wallet: 'Abstract_Wallet') -> 'EscrowWorker':
        if self.is_escrow_agent(wallet) and wallet.has_lightning():
            return EscrowAgent.create(
                wallet,
                self.nostr_worker,
                self._get_storage(wallet=wallet, purpose=StoragePurpose.AGENT_DATA),
            )
        if self.is_escrow_agent(wallet):
            self.logger.warning("wallet is flagged as escrow agent but has no "
                                "lightning support, falling back to client mode")
        return EscrowClient.create(
            wallet,
            self.nostr_worker,
            self._get_storage(wallet=wallet, purpose=StoragePurpose.CLIENT_DATA),
        )

    def _on_backup_restored(self, wallet: 'Abstract_Wallet'):
        """Called after a nostr state backup was applied to the wallet: replaces the
        running trade worker so it picks up the restored state (and agent role)."""
        with self._workers_lock:
            worker = self.wallets.get(wallet)
            if worker is None or self.nostr_worker is None:
                return  # wallet was closed while the backup was being fetched
            worker.stop()
            self.wallets[wallet] = self._create_trade_worker(wallet)
        trigger_callback('escrow_trades_updated', wallet)

    def get_backup_worker(self, wallet: 'Abstract_Wallet') -> Optional[NostrStateBackup]:
        return self.backups.get(wallet)

    @hook
    def close_wallet(self, wallet: 'Abstract_Wallet'):
        with self._workers_lock:
            if wallet in self.wallets:
                self.wallets[wallet].stop()
                del self.wallets[wallet]
            if wallet in self.backups:
                self.backups[wallet].stop()
                del self.backups[wallet]

            if not self.wallets:
                # stop nostr worker if there is no open wallet left
                if self.nostr_worker:
                    self.nostr_worker.stop()
                    self.nostr_worker = None

    def on_close(self):
        """Called when the plugin gets disabled."""
        with self._workers_lock:
            for worker in self.wallets.values():
                worker.stop()
            self.wallets.clear()
            for backup in self.backups.values():
                backup.stop()
            self.backups.clear()
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
        return isinstance(self.get_worker_for_wallet(wallet), EscrowAgent)

    def get_worker_for_wallet(self, wallet: 'Abstract_Wallet') -> Optional['EscrowWorker']:
        """Single atomic read of the current trade worker: a backup restore can swap
        the worker (and its role) from the asyncio thread at any time."""
        with self._workers_lock:
            return self.wallets.get(wallet)

    def set_escrow_agent_mode(self, *, enabled: bool, wallet: 'Abstract_Wallet'):
        if enabled and not wallet.has_lightning():
            raise UserFacingException(
                _("Acting as escrow agent requires a wallet with Lightning support."))
        with self._workers_lock:
            if wallet not in self.wallets:
                raise UserFacingException(_("Wallet is not loaded in the escrow plugin."))
            storage = self.get_storage(wallet)
            self.wallets[wallet].stop()
            storage['is_escrow_agent'] = enabled
            wallet.save_db()
            self.wallets[wallet] = self._create_trade_worker(wallet)
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
        worker = self.get_worker_for_wallet(wallet)
        if not isinstance(worker, worker_type):
            # e.g. a restored backup switched the wallet's role while a dialog was open
            raise UserFacingException(
                _("The escrow role of the wallet has changed, please close and "
                  "reopen the dialog."))
        return worker
