import asyncio
import os
import ssl
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
import json
import functools
import threading
import secrets

import irc
import irc.client_aio
import irc.client
import irc.connection
import electrum_aionostr as aionostr

from electrum.plugin import BasePlugin, hook
from electrum.util import (OldTaskGroup, make_aiohttp_proxy_connector, ca_path,
                           get_nostr_ann_pow_amount, get_asyncio_loop, log_exceptions)
from electrum.submarine_swaps import NostrTransport
import electrum.constants as constants

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.daemon import Daemon
    from electrum.wallet import Abstract_Wallet
    from electrum.network import Network
    from aiohttp_socks import ProxyConnector


@dataclass
class SwapserverStats:
    creation_time: int = field(default_factory=lambda: int(time.time()))
    swapserver_pubkeys: set = field(default_factory=set)
    events_sent_to_swapserver: int = 0
    events_sent_from_swapservers: int = 0

    @property
    def amount_swapservers(self):
        return len(self.swapserver_pubkeys)


class SwapServerMonitorBot(BasePlugin):

    def __init__(self, parent, config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.config = config
        self.wallet = None  # type: Optional[Abstract_Wallet]
        self.network = None  # type: Optional[Network]
        self.running = False
        self.taskgroup = OldTaskGroup()
        self.swapserver_stats = {}  # type: dict[int, SwapserverStats]  # starting_ts -> stats
        self.current_stats = SwapserverStats()
        self._blacklisted_pubkeys = set()  # type: set[str]  # swapservers on other networks (e.g. testnet)
        self._known_swapservers = set()  # type: set[str]

    @hook
    def daemon_wallet_loaded(self, daemon: 'Daemon', wallet: 'Abstract_Wallet'):
        if self.running:
            return
        self.wallet = wallet
        self.network = wallet.network
        asyncio.run_coroutine_threadsafe(self.taskgroup.spawn(self.run_bot()), daemon.asyncio_loop)
        self.running = True

    @hook
    def close_wallet(self, wallet):
        if not self.running:
            return
        if not wallet == self.wallet:
            return
        self.running = False
        self.wallet = None
        self.network = None
        asyncio.run_coroutine_threadsafe(self.taskgroup.cancel_remaining(), get_asyncio_loop())

    @log_exceptions
    async def run_bot(self):
        self.logger.info(f"SwapserverMonitorBot running")
        async with OldTaskGroup(wait=any) as group:
            tasks = [
                self._collect_swapserver_stats(),
                self._rollover_swapserver_stats(),
                self._publish_swapserver_stats(),
            ]
            for task in tasks:
                await group.spawn(task)
        self.logger.info(f"SwapserverMonitorBot stopped")

    async def _collect_swapserver_stats(self):
        self.logger.debug(f"collecting swapserver stats")
        async with self._nostr_manager() as manager:
            await asyncio.sleep(0.5)
            async with OldTaskGroup(wait=any) as subscription_group:
                await subscription_group.spawn(self._subscribe_offers(manager))
                await asyncio.sleep(1)
                await subscription_group.spawn(self._subscribe_direct_messages(manager))
        self.logger.info(f"stopped collecting swapserver data")

    async def _subscribe_offers(self, manager: aionostr.Manager):
        query = {
            "kinds": [NostrTransport.USER_STATUS_NIP38],
            "limit": 10,
            "#d": [f"electrum-swapserver-{NostrTransport.NOSTR_EVENT_VERSION}"],
            # "#r": [f"net:{constants.net.NET_NAME}"],
            "since": int(time.time()) - 60 * 60,
        }
        async for event in manager.get_events(query, single_event=False, only_stored=False):
            if event.pubkey in self._blacklisted_pubkeys:
                continue
            try:
                content = json.loads(event.content)
                if not isinstance(content, dict):
                    raise Exception("malformed content, not dict")
                tags = {k: v for k, v in event.tags}
            except Exception as e:
                self.logger.debug(f"failed to parse event: {e}")
                continue
            if tags.get('d') != f"electrum-swapserver-{NostrTransport.NOSTR_EVENT_VERSION}":
                continue
            if tags.get('r') != f"net:{constants.net.NET_NAME}":
                continue
            if (event.created_at > int(time.time()) + 60 * 60
                or event.created_at < int(time.time()) - 60 * 60):
                continue
            try:
                pow_nonce = int(content.get('pow_nonce', "0"), 16)  # type: int
            except Exception:
                continue
            pubkey = event.pubkey
            pow_bits = get_nostr_ann_pow_amount(bytes.fromhex(pubkey), pow_nonce)
            if pow_bits < self.config.SWAPSERVER_POW_TARGET:
                self.logger.debug(f"too low pow: {pubkey}: pow: {pow_bits} nonce: {pow_nonce}")
                continue
            for tag in event.tags:
                try:
                    if tag[0] in ['#r', 'r'] and tag[1] == f"net:{constants.net.NET_NAME}":
                        # has a tag of our network
                        break
                except IndexError:
                    continue
            else:
                # either has no tag or another network (e.g. testnet), not using this
                self._blacklisted_pubkeys.add(event.pubkey)
                continue
            self.current_stats.swapserver_pubkeys.add(pubkey)
            self._known_swapservers.add(pubkey)

    async def _subscribe_direct_messages(self, manager: aionostr.Manager):
        query = {
            "kinds": [NostrTransport.EPHEMERAL_REQUEST],
            "limit": 0,
            "since": int(time.time()),
        }
        async for event in manager.get_events(query, single_event=False, only_stored=False):
            if event.pubkey in self._blacklisted_pubkeys:
                continue
            if event.pubkey in self._known_swapservers:
                self.current_stats.events_sent_from_swapservers += 1
            elif len(event.tags) == 1:
                tag = event.tags[0]
                try:
                    if tag[0] in ['p', '#p'] \
                        and tag[1] in self._known_swapservers:
                            self.current_stats.events_sent_to_swapserver += 1
                except IndexError:
                    continue

    async def _rollover_swapserver_stats(self):
        while True:
            await asyncio.sleep(5)
            age = int(time.time()) - self.current_stats.creation_time
            if age >= self.config.SAMPLE_DURATION:  # type: ignore
                self.swapserver_stats[self.current_stats.creation_time] = self.current_stats
                self.current_stats = SwapserverStats()

    async def _publish_swapserver_stats(self):
        while True:
            await asyncio.sleep(5)
            now = int(time.time())
            publish_at = self._get_next_publication_timestamp()
            if abs(now - publish_at) < 60:
                for creation_time, stat in list(self.swapserver_stats.items()):
                    try:
                        await self._send_msg_to_irc(self._format_irc_message(stat))
                    except Exception as e:
                        self.logger.error(f"couldn't connect to IRC server, not publishing stats: {str(e)}")
                        continue
                    del self.swapserver_stats[creation_time]
                    await asyncio.sleep(20)

    @log_exceptions
    async def _send_msg_to_irc(self, msg: str):
        # todo: pretty ugly, irc has some clunky aio interface that would be better but this just worked
        self.logger.debug(f"sending irc message: {msg}")
        host, port = self.config.SWAP_MONITOR_IRC_SERVER.rsplit(":", 1)  # type: ignore
        port = int(port)
        channel = self.config.SWAP_MONITOR_IRC_CHANNEL  # type: ignore

        name_suffix = secrets.token_hex(3)
        base_nick = self.config.SWAP_MONITOR_IRC_USERNAME[:9]  # type:ignore
        nickname = f"{base_nick}-{name_suffix}"

        def run_sync_irc_client():
            try:
                reactor = irc.client.Reactor()
                message_sent = []
                error_occurred = []

                def on_welcome(connection, event):
                    self.logger.debug("IRC: Connected, joining channel")
                    connection.join(channel)

                def on_join(connection, event):
                    self.logger.debug("IRC: Joined, sending message")
                    connection.privmsg(channel, msg)
                    message_sent.append(True)

                    # Schedule disconnect after 2 seconds
                    def disconnect_later():
                        time.sleep(2)
                        connection.quit("Stats published")

                    thread = threading.Thread(target=disconnect_later)
                    thread.daemon = True
                    thread.start()

                def on_error(connection, event):
                    error_occurred.append(f"IRC error: {event.arguments}")

                def on_disconnect(connection, event):
                    self.logger.debug("IRC: Disconnected")

                try:
                    # Setup connection factory with SSL if needed
                    if port in [6697, 7000]:
                        ssl_context = ssl.create_default_context()
                        wrapper = functools.partial(
                            ssl_context.wrap_socket,
                            server_hostname=host
                        )
                        connect_factory = irc.connection.Factory(wrapper=wrapper)
                    else:
                        connect_factory = irc.connection.Factory()

                    # Create connection
                    conn = reactor.server().connect(
                        host, port, nickname,
                        connect_factory=connect_factory
                    )

                    # Add event handlers
                    conn.add_global_handler("welcome", on_welcome)
                    conn.add_global_handler("join", on_join)
                    conn.add_global_handler("error", on_error)
                    conn.add_global_handler("disconnect", on_disconnect)

                    # Process events for up to 30 seconds
                    start_time = time.time()
                    while (time.time() - start_time < 30 and
                           not message_sent and not error_occurred):
                        reactor.process_once(timeout=1)

                    # Give a bit more time for clean disconnect
                    if message_sent and not error_occurred:
                        # Wait up to 5 more seconds for disconnect
                        disconnect_time = time.time()
                        while (time.time() - disconnect_time < 5 and
                               conn.is_connected()):
                            reactor.process_once(timeout=0.1)
                        return {'success': True}
                    elif error_occurred:
                        return {'success': False, 'error': error_occurred[0]}
                    else:
                        return {'success': False, 'error': 'Timeout'}

                except Exception as e:
                    self.logger.error(f"IRC connection failed: {e}")
                    return {'success': False, 'error': str(e)}

            except Exception as e:
                self.logger.error(f"Failed to create IRC client: {e}")
                return {'success': False, 'error': str(e)}

        # Run the IRC client in a thread and wait for result
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, run_sync_irc_client)
            if not result['success']:
                raise Exception(result.get('error', 'Unknown error'))
            else:
                self.logger.debug("IRC message sent successfully")
        except Exception as e:
            self.logger.error(f"IRC message sending failed: {e}")
            raise

    def _get_next_publication_timestamp(self):
        today = datetime.now(timezone.utc)
        year = today.year
        month = today.month
        day = today.day
        hour = self.config.UTC_24H_PUBLICATION_TIME  # type: ignore
        assert 0 <= hour <= 24, "What time is this?"

        dt = datetime(year, month, day, hour, 0, 0, tzinfo=timezone.utc)
        return int(dt.timestamp())

    def _format_irc_message(self, stat: SwapserverStats) -> str:
        utc_time_start = datetime.fromtimestamp(stat.creation_time, tz=timezone.utc)
        end_timestamp = stat.creation_time + self.config.SAMPLE_DURATION  # type: ignore
        utc_time_end = datetime.fromtimestamp(end_timestamp, tz=timezone.utc)
        msg = (f"{stat.amount_swapservers} different swap servers "
               f"sent {stat.events_sent_from_swapservers} msg to clients and received "
               f"{stat.events_sent_to_swapserver} msg from clients "
               f"between {utc_time_start} and {utc_time_end} ({self.config.SAMPLE_DURATION // 3600}h)")
        return msg

    @asynccontextmanager
    async def _nostr_manager(self):
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        if self.network.proxy and self.network.proxy.enabled:
            proxy = make_aiohttp_proxy_connector(self.network.proxy, ssl_context)
        else:
            proxy: Optional['ProxyConnector'] = None
        manager_logger = self.logger.getChild('aionostr-monitor-plugin')
        manager_logger.setLevel("INFO")  # set to INFO because DEBUG is very spammy
        async with aionostr.Manager(
                relays=self.config.NOSTR_RELAYS.split(','),
                private_key=os.urandom(32).hex(),
                ssl_context=ssl_context,
                proxy=proxy,
                log=manager_logger
        ) as manager:
            yield manager



