import asyncio
import json
import time
from concurrent.futures import Future, CancelledError
import secrets
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Optional, Callable, Awaitable, Any, Set, Deque, Coroutine
from collections import deque
import ssl

import electrum_aionostr as aionostr
from electrum_aionostr.key import PrivateKey
from electrum_aionostr.event import Event as nEvent

from electrum.keystore import MasterPublicKeyMixin
from electrum.logging import Logger
from electrum.util import (
    EventListener, make_aiohttp_proxy_connector, ca_path, event_listener, get_asyncio_loop,
    run_sync_function_on_asyncio_thread
)
from electrum.wallet import Abstract_Wallet
from electrum.crypto import sha256

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.network import Network
    from electrum.util import ProxyConnector

# A job is an async function that takes the nostr manager as argument
NostrJob = Callable[['aionostr.Manager'], Coroutine[Any, Any, None]]

class EscrowNostrWorker(Logger, EventListener):
    AGENT_STATUS_EVENT_KIND = 30315

    def __init__(self, config: 'SimpleConfig', network: 'Network'):
        Logger.__init__(self)
        EventListener.__init__(self)
        self.config = config
        self.network = network
        self.main_task: Optional[Future] = None
        self.jobs: Deque[NostrJob] = deque()
        self.jobs_event = asyncio.Event()
        self.register_callbacks()

    def start(self):
        # also called by proxy changed callback
        assert self.main_task is None
        task = asyncio.run_coroutine_threadsafe(
            self.main_loop(),
            get_asyncio_loop(),
        )

        def done_callback(f):
            try:
                f.result()
            except (asyncio.CancelledError, CancelledError):
                pass
            except Exception:
                self.logger.exception("EscrowNostrWorker task failed")

        task.add_done_callback(done_callback)
        self.main_task = task
        self.logger.debug(f"Nostr worker started")

    def _add_job(self, job: NostrJob):
        def _add():
            self.jobs.append(job)
            self.jobs_event.set()
        run_sync_function_on_asyncio_thread(_add, block=False)

    async def main_loop(self):
        """
        Keeps the relay connection open while there are jobs to do. Once all jobs are done the
        connection is closed, and it waits for new jobs.
        NOTE: If the main_loop gets canceled (e.g. due to proxy change) the pending jobs will not
              get restarted, so take care to restart important tasks after restarting the main_loop.
        """
        while True:
            await self.jobs_event.wait()
            self.logger.debug("Starting new nostr manager session")
            try:
                async with self.nostr_manager() as manager:
                    running_tasks: Set[asyncio.Task] = set()
                    try:
                        while True:
                            # Start all pending jobs
                            while self.jobs:
                                job = self.jobs.popleft()
                                task = asyncio.create_task(job(manager))
                                running_tasks.add(task)

                            self.jobs_event.clear()

                            if not running_tasks:
                                # No running tasks and no pending jobs.
                                # Wait a bit for new jobs before closing connection.
                                try:
                                    await asyncio.wait_for(self.jobs_event.wait(), timeout=10.0)
                                    continue
                                except asyncio.TimeoutError:
                                    break

                            wait_objs = list(running_tasks)
                            job_waiter = asyncio.create_task(self.jobs_event.wait())
                            wait_objs.append(job_waiter)

                            try:
                                done, pending = await asyncio.wait(
                                    wait_objs,
                                    return_when=asyncio.FIRST_COMPLETED
                                )
                            except asyncio.CancelledError:
                                job_waiter.cancel()
                                raise

                            if job_waiter not in done:
                                job_waiter.cancel()  # Some task finished.

                            # Remove done tasks from running_tasks
                            for t in done:
                                if t in running_tasks:
                                    running_tasks.remove(t)
                                    if not t.cancelled() and t.exception():
                                        try:
                                            t.result()
                                        except Exception:
                                            self.logger.exception("Nostr job failed")
                    finally:
                        for t in running_tasks:
                            t.cancel()

            except Exception as e:
                self.logger.exception("Error in nostr main loop")
                await asyncio.sleep(1)

    def stop(self):
        self.unregister_callbacks()
        if self.main_task:
            if not self.main_task.cancelled():
                self.main_task.cancel()
            self.main_task = None
        self.logger.debug(f"Nostr worker stopped")

    @staticmethod
    def get_nostr_privkey_for_wallet(wallet: 'Abstract_Wallet') -> PrivateKey:
        """
        This should only be used to store application data on nostr but not as identity.
        Each trade should use a new keypair to prevent trades from getting linked to each other.
        """
        keystore = wallet.get_keystore()
        assert isinstance(keystore, MasterPublicKeyMixin)
        xpub = keystore.get_master_public_key()
        privkey = sha256('nostr_escrow:' + xpub)
        return PrivateKey(privkey)

    @asynccontextmanager
    async def nostr_manager(self):
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        if self.network.proxy and self.network.proxy.enabled:
            proxy = make_aiohttp_proxy_connector(self.network.proxy, ssl_context)
        else:
            proxy: Optional['ProxyConnector'] = None
        manager_logger = self.logger.getChild('aionostr')
        manager_logger.setLevel("INFO")  # set to INFO because DEBUG is very spammy

        relays = self.config.NOSTR_RELAYS
        relay_list = relays.split(',') if relays else []

        async with aionostr.Manager(
            relays=relay_list,
            private_key=secrets.token_hex(nbytes=32),
            ssl_context=ssl_context,
            proxy=proxy,
            log=manager_logger
        ) as manager:
            yield manager

    @event_listener
    async def on_event_proxy_set(self, *args):
        if not self.main_task:
            return
        # cannot call self.stop() as this unregisters the callbacks
        self.main_task.cancel()
        self.main_task = None
        self.start()
        self.logger.debug(f"Nostr worker restarted")

    def _broadcast_event(self, nostr_event: 'nEvent'):
        async def _job(manager: 'aionostr.Manager'):
            try:
                event_id = await manager.add_event(nostr_event)
                self.logger.debug(f"nostr event {event_id} broadcast")
            except asyncio.TimeoutError:
                self.logger.warn(f"broadcasting event {nostr_event.id} timed out")
        self._add_job(job=_job)

    def broadcast_agent_status_event(self, *, content: dict, tags: list, signing_key: PrivateKey) -> None:
        content = json.dumps(content)
        event = nEvent(
            content=content,
            kind=self.AGENT_STATUS_EVENT_KIND,
            tags=tags,
            pubkey=signing_key.public_key.hex(),
        )
        event.add_expiration_tag(expiration_ts=int(time.time()) + 7_700_000)  # ~3 months
        event.sign(signing_key.hex())
        self._broadcast_event(event)
