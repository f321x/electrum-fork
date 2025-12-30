import asyncio

from .escrow_worker import EscrowWorker

class EscrowClient(EscrowWorker):
    async def main_loop(self):
        self.logger.debug(f"escrow client started: {self.wallet.basename()}")
        while True:
            # publish nostr events
            # fetch and handle requests
            # show user notifications
            # progress trade states
            await asyncio.sleep(1)
