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
    website: Optional[str]


class EscrowAgent(EscrowWorker):
    STATUS_EVENT_INTERVAL_SEC = 1800  # 30 min
    PROFILE_EVENT_INTERVAL_SEC = 1_209_600  # 2 weeks
    RELAY_EVENT_INTERVAL_SEC = 1_209_800  # 2 weeks
    AGENT_NOSTR_PROTOCOL_VERSION = 1

    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict):
        EscrowWorker.__init__(self, wallet, nostr_worker, storage)
        # we derive a persistent nostr identity from the wallet
        self.nostr_identity_private_key = nostr_worker.get_nostr_privkey_for_wallet(wallet)

    async def main_loop(self):
        self.logger.debug(f"escrow agent started: {self.wallet.basename()}")
        tasks = (
            self._broadcast_status_event(),
            self._maybe_rebroadcast_profile_event(),
        )
        async with OldTaskGroup() as g:
            for task in tasks:
                await g.spawn(task)
                await asyncio.sleep(3)  # prevent getting rate limited by relays

    def broadcast_profile_event(self, profile_data: EscrowAgentProfile):
        content = {
            "name": profile_data.name,
            "about": profile_data.about,
            "languages": profile_data.languages,
            "service_fee_ppm": profile_data.service_fee_ppm,
        }
        if profile_data.gpg_fingerprint:
            content["gpg_fingerprint"] = profile_data.gpg_fingerprint
        if profile_data.picture:
            content["picture"] = profile_data.picture
        if profile_data.website:
            content["website"] = profile_data.website
        tags = [
            ['d', f'electrum-escrow-plugin-{str(self.AGENT_NOSTR_PROTOCOL_VERSION)}'],
            ['r', 'net:' + constants.net.NET_NAME],
        ]
        self.nostr_worker.broadcast_agent_profile_event(
            content=content,
            tags=tags,
            signing_key=self.nostr_identity_private_key,
        )

    async def _maybe_rebroadcast_profile_event(self):
        """
        Rebroadcast the profile on startup and every PROFILE_EVENT_INTERVAL_SEC to ensure
        it is always widely available on relays.
        """
        while True:
            profile_data = self.storage.get('profile')
            if profile_data:
                profile = EscrowAgentProfile(**profile_data)
                self.broadcast_profile_event(profile)
            await asyncio.sleep(self.PROFILE_EVENT_INTERVAL_SEC)

    async def _broadcast_relay_event(self):
        """
        Broadcast our list of relays from time to time to ensure clients know which
        relays the agent is active on.
        """
        previous_relays = None
        last_broadcast = 0
        while True:
            relays = self.wallet.config.get_nostr_relays()
            if relays:
                # broadcast if our relays have changed or if timeout
                if relays != previous_relays or (int(time.time()) - last_broadcast) > self.RELAY_EVENT_INTERVAL_SEC:
                    previous_relays, last_broadcast = relays, int(time.time())
                    self.nostr_worker.broadcast_agent_relay_event(
                        relays=relays,
                        signing_key=self.nostr_identity_private_key,
                    )
            await asyncio.sleep(120)

    async def _broadcast_status_event(self):
        """
        Publishes a NIP-38 status event every STATUS_EVENT_INTERVAL_SEC so clients can see the
        agent is available and useful dynamic information of the agent (like liquidity).
        """
        tags = [
            ['d', f'electrum-escrow-plugin-{str(self.AGENT_NOSTR_PROTOCOL_VERSION)}'],
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
