from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum

from electrum.i18n import _
from electrum.plugin import BasePlugin, hook
from electrum import constants

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet
    from electrum.daemon import Daemon


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
    trade_network: str  #  AbstractNet.NET_NAME


class EscrowPlugin(BasePlugin):
    # todo: check compatibility with electrum version
    # todo: check for plugin updates (nostr)

    def __init__(self, parent, config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallets = set()  # type: set[Abstract_Wallet]
        self.config = config
        self.logger.debug(f"Escrow plugin created")

    def is_escrow_agent(self, wallet: Abstract_Wallet) -> Optional[bool]:
        """Is stored in wallet db as the user might is agent in one wallet and user in another wallet"""
        storage = self.get_storage(wallet)
        return storage.get('is_escrow_agent', False)

    def set_escrow_agent_mode(self, *, enabled: bool, wallet: 'Abstract_Wallet'):
        storage = self.get_storage(wallet)
        storage['is_escrow_agent'] = enabled
        self.logger.debug(f"escrow agent mode {enabled=}")

    @hook
    def daemon_wallet_loaded(self, daemon: 'Daemon', wallet: 'Abstract_Wallet'):
        self.wallets.add(wallet)

    @hook
    def close_wallet(self, wallet: 'Abstract_Wallet'):
        self.wallets.discard(wallet)
