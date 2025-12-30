import asyncio
from dataclasses import dataclass

from .escrow_worker import EscrowWorker


@dataclass(frozen=True)
class EscrowAgentProfile:
    """
    Information broadcast by the escrow agent, visible to its customers.
    Using Nostr kind 0 (NIP-01) profile event.
    """
    name: str


class EscrowAgent(EscrowWorker):
    async def main_loop(self):
        self.logger.debug(f"escrow agent started: {self.wallet.basename()}")
        while True:
            # publish nostr events
            # fetch and handle requests
            # show user notifications
            # progress trade states
            await asyncio.sleep(1)
