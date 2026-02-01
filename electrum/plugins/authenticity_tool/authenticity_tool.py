"""This is supposed to be independent of electrum gui and plugin logic."""
import logging
import ssl
import asyncio
from contextlib import asynccontextmanager
from typing import Optional, AsyncGenerator

import electrum_ecc as ecc
import electrum_aionostr as aionostr
from electrum_aionostr.event import Event
from aiohttp_socks import ProxyConnector

from electrum.util import ca_path


class NostrFileAuthenticityTool:
    # nostr nip38 status event kind, allows to replace events by file hash
    # so there is only one event for a given file hash per pubkey
    # if the signer wants to revoke they can just replace the old event
    # and push it out of existence through their new event.
    # They can however still be hold accountable if someone stores their previous
    # event?
    NOSTR_EVENT_KIND = 8937
    SIGNING_PROTOCOL_VERSION = 1
    logger = logging.getLogger(__name__)

    @classmethod
    async def publish_signature(
        cls, *,
        file_hash_sha256: bytes,
        private_key: bytes,
        nostr_relays: set[str],
        proxy: Optional['ProxyConnector'],
    ):
        assert isinstance(file_hash_sha256, bytes) and len(file_hash_sha256) == 32
        assert isinstance(private_key, bytes) and len(private_key) == 32
        private_key = ecc.ECPrivkey(private_key)
        # the tags are covered by the events signature
        tags = [['d', f"{file_hash_sha256.hex()}:{cls.SIGNING_PROTOCOL_VERSION}"]]
        signing_event = Event(
            pubkey=private_key.get_public_key_hex()[2:],
            kind=cls.NOSTR_EVENT_KIND,
            content="",
            tags=tags,
        )
        signing_event = signing_event.sign(private_key.get_secret_bytes().hex())
        async with cls._nostr_manager(
            nostr_relays=nostr_relays,
            # passing the private key might increase the chances of the event being accepted by relays
            # as it will allow aionostr to authenticate with relays
            private_key=private_key.get_secret_bytes(),
            proxy=proxy,
        ) as man:
            if not man.relays:
                raise ConnectionError("couldn't connect to relays")
            event_id = await man.add_event(signing_event)
            await asyncio.sleep(0.5)  # wait a bit more before closing the connection
        NostrFileAuthenticityTool.logger.info(
            f"signature for file {file_hash_sha256.hex()} published successfully: {event_id=}!"
        )

    @classmethod
    async def verify_hash(
        cls, *,
        file_hash_sha256: bytes,
        trusted_signing_pubkeys_hex: set[str],
        timeout_sec: int,  # this is independent of the relay connection timeout
        nostr_relays: set[str],
        proxy: Optional['ProxyConnector'],
    ) -> AsyncGenerator[str, None]:  # yields the pubkeys of successfull signers
        """
        If there is no valid signature for a given hash there won't be a _negative_
        result, there will just be no valid signature event for this hash. So after the
        timeout or when all relays returned EOSE we can assume there is no signature
        (or the user has a bad internet connection).
        """
        assert isinstance(file_hash_sha256, bytes) and len(file_hash_sha256) == 32
        assert all(isinstance(pk, str) for pk in trusted_signing_pubkeys_hex)
        assert all(len(pk) == 64 for pk in trusted_signing_pubkeys_hex)
        assert 1 < timeout_sec < 500, "useless timeout"
        seen_pubkeys = {}  # type: dict[str, Event]
        file_d_tag = f"{file_hash_sha256.hex()}:{cls.SIGNING_PROTOCOL_VERSION}"
        query = {
            "kinds": [cls.NOSTR_EVENT_KIND],
            "authors": [pk for pk in trusted_signing_pubkeys_hex],
            "#d": [file_d_tag],
        }
        async with cls._nostr_manager(
            nostr_relays=nostr_relays,
            proxy=proxy,
            private_key=None,
        ) as man:
            try:
                async with asyncio.timeout(timeout_sec):
                    async for signing_event in man.get_events(
                        query,
                        single_event=False,
                        only_stored=True,
                    ):
                        if not signing_event.pubkey in trusted_signing_pubkeys_hex:
                            cls.logger.debug(f"invalid pubkey {signing_event.pubkey}")
                            continue
                        if signing_event.pubkey in seen_pubkeys:
                            cls.logger.debug(f"signing pubkey already seen")
                            # allow only one signature per pubkey per hash
                            continue
                        if not any(tag == ['d', file_d_tag] for tag in signing_event.tags):
                            cls.logger.debug(f"no file d tag in event, is the relay trolling us?")
                            continue
                        assert signing_event.verify(), "should have been verified by aionostr"
                        seen_pubkeys[signing_event.pubkey] = signing_event
                        NostrFileAuthenticityTool.logger.info(
                            f"found signature for file {file_hash_sha256.hex()} "
                            f"from {signing_event.pubkey}: {signing_event.id=}!"
                        )
                        yield signing_event.pubkey
            except asyncio.TimeoutError:
                return
            finally:
                # naively rebroadcast to all our relays, they will probably already have this
                # but this should ensure maximum spread and availability of the signing event
                try:
                    for found_event in seen_pubkeys.values():
                        await man.add_event(found_event)
                        NostrFileAuthenticityTool.logger.debug(f"rebroadcast signing event {found_event.id}")
                        if len(seen_pubkeys) > 1:
                            await asyncio.sleep(1)  # relays are rate limiting if we blast them in a loop
                except asyncio.TimeoutError:
                    pass

    @staticmethod
    @asynccontextmanager
    async def _nostr_manager(
        *,
        nostr_relays: set[str],
        private_key: Optional[bytes],  # only useful for signer to authenticate with relays
        proxy: Optional['ProxyConnector'],
    ) -> AsyncGenerator[aionostr.Manager, None]:
        assert isinstance(proxy, ProxyConnector) or proxy is None, proxy
        assert nostr_relays, "No relays?"
        assert private_key is None or (isinstance(private_key, bytes) and len(private_key) == 32)
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        log = NostrFileAuthenticityTool.logger.getChild('aionostr')
        if private_key is None:  # when signing allow debug mode, might be insightful for signers
            log.setLevel('INFO')  # debug is very spammy
        async with aionostr.Manager(
            relays=list(nostr_relays),
            private_key=private_key.hex() if private_key else None,
            ssl_context=ssl_context,
            proxy=proxy,
            log=log,
        ) as manager:
            if not manager.relays:
                # manager replaces relays with the ones that did successfully connect
                raise ConnectionError(f"couldn't connect to relays")
            yield manager
