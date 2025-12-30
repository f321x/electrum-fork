import time
from typing import TYPE_CHECKING, Optional
import asyncio
from dataclasses import dataclass

from electrum.util import OldTaskGroup
from electrum import constants

from .escrow_worker import EscrowWorker

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
    gpg_fingerprint: Optional[str]
    picture: Optional[str]  # url to profile picture


class EscrowAgent(EscrowWorker):
    STATUS_EVENT_INTERVAL_SEC = 1800  # 30 min
    AGENT_STATUS_EVENT_VERSION = 1

    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker'):
        EscrowWorker.__init__(self, wallet, nostr_worker)
        # we derive a persistent nostr identity from the wallet
        self.nostr_identity_private_key = nostr_worker.get_nostr_privkey_for_wallet(wallet)
        self.profile_changed = asyncio.Event()

    async def main_loop(self):
        self.logger.debug(f"escrow agent started: {self.wallet.basename()}")
        tasks = [
            self.broadcast_profile_event()
        ]
        async with OldTaskGroup() as g:
            for task in tasks:
                await g.spawn(task)
                await asyncio.sleep(3)  # prevent getting rate limited by relays
            # publish nostr events
            # fetch and handle requests
            # show user notifications
            # progress trade states
            await asyncio.sleep(1)

    async def broadcast_profile_event(self):
        # get profile data from db/gui
        # broadcast once every now and then
        # while True:
        pass

    async def broadcast_status_event(self):
        """
        Publishes a NIP-38 status event every STATUS_EVENT_INTERVAL_SEC so clients can see the
        agent is available and useful dynamic information of the agent (like liquidity).
        """
        tags = [
            ['d', f'electrum-escrow-plugin-{str(self.AGENT_STATUS_EVENT_VERSION)}'],
            ['r', 'net:' + constants.net.NET_NAME],
        ]
        while True:
            content = {
                'inbound_liquidity_sat': self._keep_leading_digits(self.wallet.lnworker.num_sats_can_receive() or 0, 2),
                'outbound_liquidity_sat': self._keep_leading_digits(self.wallet.lnworker.num_sats_can_receive() or 0, 2),
            }
            self.nostr_worker.broadcast_agent_status_event(
                content=content,
                tags=tags,
                signing_key=self.nostr_identity_private_key,
            )
            await asyncio.sleep(self.STATUS_EVENT_INTERVAL_SEC)

    @staticmethod
    def _keep_leading_digits(num: int, digits: int) -> int:
        """Reduces precision of num to `digits` leading digits."""
        if num <= 0:
            return 0
        num_str = str(num)
        zeroed_num_str = f"{num_str[:digits]}{(len(num_str[digits:])) * '0'}"
        return int(zeroed_num_str)
