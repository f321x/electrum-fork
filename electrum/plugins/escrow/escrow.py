from typing import Optional, TYPE_CHECKING, Dict
from dataclasses import dataclass
from enum import Enum

from electrum.i18n import _
from electrum.plugin import BasePlugin, hook

from .nostr_worker import EscrowNostrWorker
from .agent import EscrowAgent
from .client import EscrowClient

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet
    from electrum.daemon import Daemon
    from .escrow_worker import EscrowWorker


class TradeState(Enum):
    SETUP = 0
    ONGOING = 1
    MEDIATION = 2
    FINISHED = 3

    def __str__(self):
        return {
            self.SETUP: _("Setup"),
            self.ONGOING: _("Ongoing"),
            self.MEDIATION: _("Mediation"),
            self.FINISHED: _("Finished"),
        }[self]


class TradePaymentProtocol(Enum):
    BITCOIN_ONCHAIN = 0
    BITCOIN_LIGHTNING = 1


@dataclass(frozen=True)
class TradeParticipants:
    maker_pubkey: str
    taker_pubkey: str
    escrow_agent_pubkey: str


@dataclass(frozen=True)
class EscrowTrade:
    trade_id: str  # random hex string as unique id
    state: TradeState
    trade_participants: TradeParticipants
    title: str
    contract: str
    trade_amount_sat: int
    # the bond ensures both participants have something to lose
    bond_sat: int
    payment_protocol: TradePaymentProtocol
    payment_network: str  #  AbstractNet.NET_NAME


class EscrowPlugin(BasePlugin):
    MAX_CONTRACT_LEN_CHARS = 2000
    ICON_FILE_NAME = "escrow-icon.png"
    # todo: check compatibility with electrum version
    # todo: check for plugin updates (nostr)
    # todo: telegram bot notification
    # todo: onchain support (with taproot)

    def __init__(self, parent, config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallets = {}  # type: Dict[Abstract_Wallet, EscrowWorker]
        self.config = config
        self.nostr_worker = None  # type: Optional[EscrowNostrWorker]
        self.logger.debug(f"Escrow plugin created")

    def is_available(self) -> bool:
        network_available = not self.config.NETWORK_OFFLINE
        if not network_available:
            self.logger.warning(f"Escrow Plugin unavailable: no network")
        return network_available

    def is_escrow_agent(self, wallet: 'Abstract_Wallet') -> Optional[bool]:
        """Is stored in wallet db as the user might is agent in one wallet and user in another wallet"""
        storage = self.get_storage(wallet)
        return storage.get('is_escrow_agent', False)

    def set_escrow_agent_mode(self, *, enabled: bool, wallet: 'Abstract_Wallet'):
        storage = self.get_storage(wallet)
        self.wallets[wallet].stop()
        storage['is_escrow_agent'] = enabled
        if enabled:
            self.wallets[wallet] = EscrowAgent.create(wallet, self.nostr_worker)
        else:
            self.wallets[wallet] = EscrowClient.create(wallet, self.nostr_worker)
        self.logger.debug(f"escrow agent mode {enabled=}")

    @hook
    def daemon_wallet_loaded(self, daemon: 'Daemon', wallet: 'Abstract_Wallet'):
        if not self.nostr_worker:
            # create shared nostr worker for all wallets
            self.nostr_worker = EscrowNostrWorker(self.config, daemon.network)
            self.nostr_worker.start()

        if self.is_escrow_agent(wallet):
            worker = EscrowAgent.create(wallet, self.nostr_worker)
        else:
            worker = EscrowClient.create(wallet, self.nostr_worker)
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
