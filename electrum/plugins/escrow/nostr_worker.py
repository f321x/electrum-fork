import asyncio
import json
import time
from concurrent.futures import Future, CancelledError
import secrets
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Optional, Callable, Any, Set, Deque, Coroutine, Sequence, Tuple
from collections import deque
import ssl

import electrum_aionostr as aionostr
from electrum_aionostr.key import PrivateKey
from electrum_aionostr.event import Event as nEvent

from electrum.logging import Logger
from electrum.util import (
    EventListener, make_aiohttp_proxy_connector, ca_path, event_listener, get_asyncio_loop,
    run_sync_function_on_asyncio_thread, wait_for2
)
from electrum import constants
from .constants import (
    AGENT_STATUS_EVENT_KIND, AGENT_PROFILE_EVENT_KIND, AGENT_RELAY_LIST_METADATA_KIND,
    EPHEMERAL_REQUEST_EVENT_KIND, ENCRYPTED_DIRECT_MESSAGE_KIND, PROTOCOL_VERSION
)

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.network import Network
    from electrum.util import ProxyConnector

# A job is an async function that takes the nostr manager as argument
NostrJob = Callable[['aionostr.Manager'], Coroutine[Any, Any, None]]

class NostrJobID(str): pass


class SeenEventIdCache:
    """Bounded cache of nostr event ids, used to detect events that relays
    (re)serve multiple times."""

    def __init__(self, max_size: int):
        self._max_size = max_size
        self._seen: Set[str] = set()
        self._order: Deque[str] = deque()

    def seen_before(self, event_id: str) -> bool:
        """Returns whether the event id was seen before, and remembers it."""
        if event_id in self._seen:
            return True
        self._seen.add(event_id)
        self._order.append(event_id)
        if len(self._order) > self._max_size:
            oldest = self._order.popleft()
            self._seen.discard(oldest)
        return False

def get_net_tag() -> list:
    return ['r', f"net:{constants.net.NET_NAME}"]

def get_protocol_tag() -> list:
    return ['d', f"electrum-escrow-plugin-{PROTOCOL_VERSION}"]

def event_matches_net(event: 'nEvent') -> bool:
    """Returns False if the event carries an 'r' net tag of a different bitcoin network."""
    for tag in event.tags:
        if len(tag) >= 2 and tag[0] == 'r' and tag[1].startswith("net:"):
            if tag[1] != f"net:{constants.net.NET_NAME}":
                return False
    return True


class EscrowNostrWorker(Logger, EventListener):
    def __init__(self, config: 'SimpleConfig', network: 'Network'):
        Logger.__init__(self)
        EventListener.__init__(self)
        self.config = config
        self.network = network
        self.main_task: Optional[Future] = None
        self.jobs: Deque[Tuple[NostrJobID, NostrJob]] = deque()
        self.jobs_event = asyncio.Event()
        self.running_tasks: Set[asyncio.Task] = set()
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
        self.logger.debug("Nostr worker started")

    def _add_job(self, job: NostrJob) -> NostrJobID:
        job_id = NostrJobID(secrets.token_hex(8))
        def _add():
            self.jobs.append((job_id, job))
            self.jobs_event.set()
        run_sync_function_on_asyncio_thread(_add, block=False)
        return job_id

    def cancel_job(self, job_id: NostrJobID):
        def _cancel():
            # check pending jobs
            for item in list(self.jobs):
                if item[0] == job_id:
                    self.jobs.remove(item)
                    return
            # check running tasks
            for task in self.running_tasks:
                if task.get_name() == job_id:
                    task.cancel()
                    return
        run_sync_function_on_asyncio_thread(_cancel, block=False)

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
                    try:
                        while True:
                            # Start all pending jobs
                            while self.jobs:
                                job_id, job = self.jobs.popleft()
                                task = asyncio.create_task(job(manager))
                                task.set_name(job_id)
                                self.running_tasks.add(task)

                            self.jobs_event.clear()

                            if not self.running_tasks:
                                # No running tasks and no pending jobs.
                                # Wait a bit for new jobs before closing connection.
                                try:
                                    await asyncio.wait_for(self.jobs_event.wait(), timeout=10.0)
                                    continue
                                except asyncio.TimeoutError:
                                    break

                            wait_objs = list(self.running_tasks)
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
                                if t in self.running_tasks:
                                    self.running_tasks.remove(t)
                                    if not t.cancelled() and t.exception():
                                        try:
                                            t.result()
                                        except Exception:
                                            self.logger.exception("Nostr job failed")
                    finally:
                        for t in self.running_tasks:
                            t.cancel()
                        self.running_tasks.clear()

            except Exception:
                self.logger.exception("Error in nostr main loop")
                await asyncio.sleep(1)

    def stop(self):
        self.unregister_callbacks()
        if self.main_task:
            if not self.main_task.cancelled():
                self.main_task.cancel()
            self.main_task = None
        self.logger.debug("Nostr worker stopped")

    @asynccontextmanager
    async def nostr_manager(self):
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        if self.network.proxy and self.network.proxy.enabled:
            proxy = make_aiohttp_proxy_connector(self.network.proxy, ssl_context)
        else:
            proxy: Optional['ProxyConnector'] = None
        manager_logger = self.logger.getChild('aionostr')
        manager_logger.setLevel("INFO")  # set to INFO because DEBUG is very spammy

        async with aionostr.Manager(
            relays=self.config.get_nostr_relays(),
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
        self.logger.debug("Nostr worker restarted")

    def fetch_events(self, query: dict, output_queue: asyncio.Queue) -> NostrJobID:
        async def _job(manager: 'aionostr.Manager'):
            try:
                async for event in manager.get_events(
                    query,
                    single_event=False,
                    only_stored=False,
                ):
                    if event.is_expired():
                        # don't trust relays to drop expired events
                        continue
                    await output_queue.put(event)
            finally:  # put None in the queue when the query ends in case the job gets canceled
                asyncio.create_task(output_queue.put(None))
        return self._add_job(job=_job)

    def _broadcast_event(self, nostr_event: 'nEvent', on_result: Optional[Callable[[bool], None]] = None):
        """Queues the event for broadcast. on_result is called with whether at least one
        relay accepted the event (but not at all if the job gets dropped, e.g. on shutdown)."""
        async def _job(manager: 'aionostr.Manager'):
            success = False
            try:
                event_id = await manager.add_event(nostr_event)
                self.logger.debug(f"nostr event {event_id} broadcast")
                success = True
            except asyncio.TimeoutError:
                self.logger.warning(f"broadcasting event {nostr_event.id} timed out")
            finally:
                if on_result:
                    on_result(success)
        self._add_job(job=_job)

    @staticmethod
    def _prepare_event(
        *,
        kind: int,
        content: dict | str,
        tags: list,
        signing_key: PrivateKey,
        expiration_ts: Optional[int] = None,
        created_at: Optional[int] = None,
    ) -> nEvent:
        if isinstance(content, dict):
            content = json.dumps(content)
        optional_fields = {'created_at': created_at} if created_at is not None else {}
        event = nEvent(
            content=content,
            kind=kind,
            tags=tags,
            pubkey=signing_key.public_key.hex(),
            **optional_fields,
        )
        if expiration_ts:
            event = event.add_expiration_tag(expiration_ts=expiration_ts)
        event = event.sign(signing_key.hex())
        return event

    def send_encrypted_direct_message(
        self,
        *,
        cleartext_content: dict,
        recipient_pubkey: str,
        expiration_duration: int,
        signing_key: PrivateKey,
    ) -> str:
        cleartext_msg = json.dumps(cleartext_content)
        encrypted_content = signing_key.encrypt_message(cleartext_msg, recipient_pubkey)
        expiration_ts = int(time.time()) + expiration_duration
        tags = [['p', recipient_pubkey]]
        event = self._prepare_event(
            kind=ENCRYPTED_DIRECT_MESSAGE_KIND,
            content=encrypted_content,
            tags=tags,
            signing_key=signing_key,
            expiration_ts=expiration_ts,
        )
        self._broadcast_event(event)
        return event.id

    def prepare_encrypted_ephemeral_message(
        self,
        *,
        cleartext_content: dict,
        recipient_pubkey: str,
        response_to_id: Optional[str] = None,
        signing_key: PrivateKey,
    ) -> nEvent:
        cleartext_msg = json.dumps(cleartext_content)
        encrypted_content = signing_key.encrypt_message(cleartext_msg, recipient_pubkey)
        tags = [
            ['p', recipient_pubkey],
            get_net_tag(),
            get_protocol_tag(),
        ]
        if response_to_id:
            tags.append(['e', response_to_id])
        event = self._prepare_event(
            kind=EPHEMERAL_REQUEST_EVENT_KIND,
            content=encrypted_content,
            tags=tags,
            signing_key=signing_key,
        )
        return event

    def send_encrypted_ephemeral_message(
        self,
        *,
        cleartext_content: dict,
        recipient_pubkey: str,
        response_to_id: Optional[str] = None,
        signing_key: PrivateKey,
    ):
        event = self.prepare_encrypted_ephemeral_message(
            cleartext_content=cleartext_content,
            recipient_pubkey=recipient_pubkey,
            response_to_id=response_to_id,
            signing_key=signing_key,
        )
        self._broadcast_event(event)

    async def send_encrypted_ephemeral_message_and_await_response(
        self,
        *,
        cleartext_content: dict,
        recipient_pubkey: str,
        response_to_id: Optional[str] = None,
        signing_key: PrivateKey,
        timeout_sec: int,
    ) -> dict:
        """
        Sends an ephemeral request and awaits a response. Might raise TimeoutError.
        Raises ValueError on a malformed response.
        """
        event = self.prepare_encrypted_ephemeral_message(
            cleartext_content=cleartext_content,
            recipient_pubkey=recipient_pubkey,
            response_to_id=response_to_id,
            signing_key=signing_key,
        )
        query = {
            "kinds": [EPHEMERAL_REQUEST_EVENT_KIND],
            "#p": [signing_key.public_key.hex()],
            "#e": [event.id],
            "since": int(time.time()) - 1,
            "limit": 1,
        }

        response_queue = asyncio.Queue()
        job_id = self.fetch_events(query, response_queue)
        self._broadcast_event(event)
        deadline = time.monotonic() + timeout_sec
        while True:
            try:
                if not job_id:
                    job_id = self.fetch_events(query, response_queue)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    try:
                        resp_event = await wait_for2(response_queue.get(), timeout=remaining)
                    except (asyncio.TimeoutError, TimeoutError):
                        raise TimeoutError()

                    if resp_event is None:
                        # job got cancelled (e.g. proxy change), resubscribe in outer loop
                        break

                    if resp_event.pubkey != recipient_pubkey:
                        continue

                    # don't rely on relay-side filtering: check the response references our request
                    if not any(len(t) >= 2 and t[0] == 'e' and t[1] == event.id for t in resp_event.tags):
                        continue

                    try:
                        response_content = signing_key.decrypt_message(resp_event.content, recipient_pubkey)
                        response_content = json.loads(response_content)
                        if not isinstance(response_content, dict):
                            raise Exception("malformed content, not dict")
                    except Exception as e:
                        raise ValueError(e)

                    return response_content
            finally:
                if job_id:
                    self.cancel_job(job_id)
                    job_id = None

    def broadcast_replaceable_event(
        self,
        *,
        kind: int,
        content: str,
        d_tag: str,
        signing_key: PrivateKey,
        created_at: Optional[int] = None,
        on_result: Optional[Callable[[bool], None]] = None,
    ) -> None:
        """Broadcasts a parameterized replaceable event (NIP-01): relays keep the
        event with the newest created_at per (pubkey, kind, d tag)."""
        event = self._prepare_event(
            kind=kind,
            content=content,
            tags=[['d', d_tag]],
            signing_key=signing_key,
            created_at=created_at,
        )
        self._broadcast_event(event, on_result=on_result)

    def broadcast_agent_status_event(self, *, content: dict, tags: list, signing_key: PrivateKey) -> None:
        event = self._prepare_event(
            kind=AGENT_STATUS_EVENT_KIND,
            content=content,
            tags=tags,
            signing_key=signing_key,
            expiration_ts=int(time.time()) + 2_600_000,  # ~1 month
        )
        self._broadcast_event(event)

    def broadcast_agent_profile_event(self, *, content: dict, tags: list, signing_key: PrivateKey) -> None:
        event = self._prepare_event(
            kind=AGENT_PROFILE_EVENT_KIND,
            content=content,
            tags=tags,
            signing_key=signing_key,
            expiration_ts=int(time.time()) + 7_700_000,  # ~3 months
        )
        self._broadcast_event(event)

    def broadcast_agent_relay_event(self, *, relays: Sequence[str], signing_key: PrivateKey) -> None:
        tags = [['r', relay_url] for relay_url in relays]
        event = self._prepare_event(
            kind=AGENT_RELAY_LIST_METADATA_KIND,
            content='',
            tags=tags,
            signing_key=signing_key,
            expiration_ts=int(time.time()) + 7_700_000,  # ~3 months
        )
        self._broadcast_event(event)
