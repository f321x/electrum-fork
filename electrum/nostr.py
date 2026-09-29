import ssl
from typing import TYPE_CHECKING, Iterable, Optional, Tuple

from electrum_aionostr import RelayPool, NostrSession

from .logging import Logger
from .util import (
    EventListener, event_listener, ca_path, get_asyncio_loop, get_running_loop,
    make_aiohttp_proxy_connector, ignore_exceptions, log_exceptions,
)

if TYPE_CHECKING:
    from aiohttp_socks import ProxyConnector
    from .network import Network


class NostrManager(Logger, EventListener):
    """
    Owns the process-wide nostr RelayPool, so that all features (swaps, plugins, ...) share
    one connection per relay. Nothing connects until the first session is opened.
    """
    LINGER_SEC = 180  # keep unused relay connections this long, in case they are needed again

    def __init__(self, network: 'Network'):
        Logger.__init__(self)
        self.network = network
        self.config = network.config
        self._ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        self._pool = None  # type: Optional[RelayPool]
        self._stopped = False
        self.register_callbacks()

    def open_session(
        self,
        *,
        name: str,
        extra_relays: Iterable[str] = (),
        use_default_relays: bool = True,
    ) -> NostrSession:
        """A session on the configured relays (NOSTR_RELAYS) plus extra_relays. Close it when done."""
        assert get_running_loop() == get_asyncio_loop(), "must be called on the asyncio thread"
        if self._stopped:
            raise Exception("nostr manager already stopped")
        if self._pool is None:
            proxy, connect_timeout = self._get_proxy()
            aionostr_logger = self.logger.getChild('aionostr')
            aionostr_logger.setLevel('INFO')  # DEBUG is very verbose
            self._pool = RelayPool(
                log=aionostr_logger,
                ssl_context=self._ssl_context,
                proxy=proxy,
                connect_timeout=connect_timeout,
                linger_sec=self.LINGER_SEC,
            )
            self._pool.set_default_relays(self.config.get_nostr_relays())
        return self._pool.open_session(name=name, extra_relays=extra_relays, use_default_relays=use_default_relays)

    @ignore_exceptions  # do not kill the teardown of the network
    @log_exceptions
    async def stop(self) -> None:
        self._stopped = True
        self.unregister_callbacks()
        if self._pool is not None:
            await self._pool.close()

    def _get_proxy(self) -> Tuple[Optional['ProxyConnector'], float]:
        proxy = self.network.proxy
        if proxy and proxy.enabled:
            return make_aiohttp_proxy_connector(proxy, self._ssl_context), 10
        return None, 5

    @event_listener
    async def on_event_proxy_set(self, *args):
        if self._stopped or self._pool is None:
            return  # the pool gets created with the current proxy
        proxy, connect_timeout = self._get_proxy()
        await self._pool.set_proxy(proxy, connect_timeout=connect_timeout)

    @event_listener
    def on_event_nostr_relays_changed(self, *args):
        if self._stopped or self._pool is None:
            return
        self._pool.set_default_relays(self.config.get_nostr_relays())
