from electrum.plugin import BasePlugin, hook
from electrum.logging import Logger
from electrum.util import log_exceptions, ca_path
from electrum.commands import command
from electrum.lnaddr import lndecode
import electrum_aionostr as aionostr
from electrum_aionostr.key import PublicKey, PrivateKey

import asyncio
import json
import time
import ssl
import urllib.parse

from typing import TYPE_CHECKING, Optional, NamedTuple

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.daemon import Daemon
    from electrum.wallet import Abstract_Wallet


class NWCClient(NamedTuple):
    our_secret_hex: str
    budget_sat_24h: int
    valid_until: int


class NWCServerPlugin(BasePlugin):
    URI_SCHEME = 'nostr+walletconnect://'

    def __init__(self, parent, config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.config = config
        self.relays = config.NOSTR_RELAYS.split(',')
        self.tokens = None # type: Optional[dict]
        self.nwc_server = None  # type: Optional[NWCServer]
        self.logger.debug(f"NWCServerPlugin created")

    @hook
    def daemon_wallet_loaded(self, daemon: 'Daemon', wallet: 'Abstract_Wallet'):
        # we use the first wallet loaded
        self.tokens = wallet.db.get_dict('nostr_wallet_connect_secrets')
        if len(self.tokens) == 0:
            new_connection = self.create_connection(100000)
            self.logger.info(f"Created new nwc connection: {new_connection}")
        self.nwc_server = NWCServer(self.config, wallet, self.tokens, self.relays)
        asyncio.run_coroutine_threadsafe(daemon.taskgroup.spawn(self.nwc_server.run()), daemon.asyncio_loop)

    # @command('')
    def create_connection(self, budget_sat_24h: int = None, valid_for_seconds: int = None) -> str:
        if self.tokens is None:
            return "Wallet not loaded"
        if not budget_sat_24h or budget_sat_24h < 1:
            return "Provide a valid 24h budget in satoshis"

        our_connection_secret = PrivateKey()
        our_connection_pubkey = our_connection_secret.public_key.hex()

        client_secret = PrivateKey()
        client_pubkey = client_secret.public_key.hex()
        if valid_for_seconds:
            valid_until = int(time.time()) + valid_for_seconds
        else:
            valid_until = 0
        # self.tokens[client_pubkey] = NWCClient(our_connection_secret.hex(), budget_sat_24h, valid_until)
        self.tokens[client_pubkey] = our_connection_secret.hex()
        connection_string = self.serialize_connection_uri(client_secret.hex(), our_connection_pubkey)

        return "\n-------\nNWC connection URI:\n" + connection_string + "\n-------"

    @command('')
    def remove_connection(self, uri_or_pubkey: str = None):
        pass

    @command('')
    def list_connections(self) -> str:
        pass

    def serialize_connection_uri(self, client_secret_hex: str, our_pubkey_hey: str) -> str:
        base_uri = f"nostr+walletconnect://{our_pubkey_hey}"

        # Create the query parameters
        query_params = []

        # Add each relay as a URL-encoded parameter
        for relay in self.relays:
            query_params.append(f"relay={urllib.parse.quote(relay)}")

        # Add the client secret
        query_params.append(f"secret={client_secret_hex}")

        # Construct the final URI
        query_string = "&".join(query_params)
        uri = f"{base_uri}?{query_string}"

        return uri

    def deserialize_connection_string(self, connection_string: str) -> tuple:
        pass

class NWCServer(Logger):
    INFO_EVENT_KIND: int        = 13194
    REQUEST_EVENT_KIND: int     = 23194
    RESPONSE_EVENT_KIND: int    = 23195
    NOTIFICATION_EVENT_KIND: int = 23196
    SUPPORTED_METHODS: list[str] = ['pay_invoice']

    def __init__(self, config: 'SimpleConfig', wallet: 'Abstract_Wallet', tokens: dict, relays: list[str]):
        Logger.__init__(self)
        self.config = config
        self.wallet = wallet
        self.tokens = tokens
        self.relays = relays
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        self.manager = aionostr.Manager(
            self.relays,
            private_key=PrivateKey(),  # use random private key
            log=self.logger,
            ssl_context=ssl_context,
        )
        assert len(relays[0]) > 1, f"{relays}"

    @log_exceptions
    async def run(self):
        while not self.tokens:
            await asyncio.sleep(5)
        await self.manager.connect()
        if not self.manager.relays:
            raise ConnectionError("No relays connected")
        self.logger.info(f"Nostr Wallet Connect server running")
        await self.publish_info_event()
        await self.handle_requests()

    async def handle_requests(self):
        query = {
            "authors": list(self.tokens.keys()),  # the pubkeys of the client connections
            "kinds": [self.REQUEST_EVENT_KIND],
            "limit": 0,
            "since": int(time.time())
        }
        async for event in self.manager.get_events(query, single_event=False, only_stored=False):
            if event.kind != self.REQUEST_EVENT_KIND:
                self.logger.debug(f"Unknown nwc request event kind: {event.kind}")
                asyncio.create_task(self.send_error(event.pubkey, "NOT_IMPLEMENTED", event.id))
                continue
            if event.pubkey not in self.tokens:
                self.logger.debug(f"Unknown nwc client pubkey: {event.pubkey}")
                asyncio.create_task(self.send_error(event.pubkey, "UNAUTHORIZED", event.id))
                continue
            if event.created_at < int(time.time()) - 15:
                self.logger.debug(f"old nwc request event: {event.content}")
                continue
            try:
                our_connection_secret = PrivateKey(raw_secret=bytes.fromhex(self.tokens[event.pubkey]))
                content = our_connection_secret.decrypt_message(event.content, event.pubkey)
                content = json.loads(content)
            except Exception:
                self.logger.debug(f"Invalid request event content: {event.content}", exc_info=True)
                continue

            method = content.get('method', "")
            if method not in self.SUPPORTED_METHODS:
                self.logger.debug(f"Unsupported method in nwc request: {content.get('method')}")
                asyncio.create_task(self.send_error(event.pubkey, "NOT_IMPLEMENTED", event.id))
                continue
            if method == "pay_invoice":
                asyncio.create_task(self.handle_pay_invoice(event.pubkey, content.get('params', {}), event.id))

    async def send_error(self, to_pubkey_hex: str, error_type: str, response_to_id: str, error_msg: str = ""):
        content = json.dumps({
            "error": {
                "code": error_type,
                "message": error_msg
            }
        })
        await self.send_encrypted_response(to_pubkey_hex, content, response_to_id)

    async def send_encrypted_response(self, to_pubkey_hex: str, content: str, response_event_id: str):
        our_connection_secret = PrivateKey(raw_secret=bytes.fromhex(self.tokens[to_pubkey_hex]))
        encrypted_content = our_connection_secret.encrypt_message(content, to_pubkey_hex)
        tags = [['p', to_pubkey_hex], ['e', response_event_id]]
        event_id = await aionostr._add_event(
            self.manager,
            kind=self.RESPONSE_EVENT_KIND,
            tags=tags,
            content=encrypted_content,
            # use the private key we generated for this specific client
            private_key=our_connection_secret.hex()
        )

    @log_exceptions
    async def handle_pay_invoice(self, author_pubkey_hex: str, params: dict, request_event_id: str):
        invoice = params.get('invoice', "")
        amount_msat = params.get('amount')
        if not invoice:
            return await self.send_error(author_pubkey_hex, "INTERNAL", request_event_id)
        try:
            # TODO: check budget and expiration time
            success, log = await self.wallet.lnworker.pay_invoice(invoice=invoice, amount_msat=amount_msat)
        except Exception:
            self.logger.debug(f"failed to pay nwc invoice", exc_info=True)
            return await self.send_error(author_pubkey_hex, "INTERNAL", request_event_id)
        lnaddr = lndecode(invoice)
        preimage = self.wallet.lnworker.get_preimage(lnaddr.paymenthash)
        response = {'result_type': 'pay_invoice'}
        if not success or not preimage:
            response['error'] = {
                'code': 'PAYMENT_FAILED',
                'message': str(log)
            }
        else:
            response['result'] = {
                'preimage': preimage.hex(),
            }
        content = json.dumps(response)
        await self.send_encrypted_response(author_pubkey_hex, content, request_event_id)
        if success:
            self.logger.info(f"paid invoice request from NWC for {lnaddr.get_amount_sat()} sat")
        else:
            self.logger.info(f"failed to pay invoice request from NWC: {log}")

    @log_exceptions
    async def publish_info_event(self):
        for client_pubkey, our_secret in self.tokens.items():



            event_id = await aionostr._add_event(
                self.manager,
                kind=self.INFO_EVENT_KIND,
                tags=None,  # only needed if we support notification events
                content=' '.join(self.SUPPORTED_METHODS),
                # use the private key we generated for this specific client
                # private_key=client.our_secret_hex,
                private_key=our_secret
            )
            self.logger.debug(f"Published info event {event_id} to {client_pubkey}")
