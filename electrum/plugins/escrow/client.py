import asyncio
import dataclasses
import time
import json
from collections import defaultdict
from typing import TYPE_CHECKING, Mapping, Optional
from types import MappingProxyType

from electrum_aionostr.event import Event as nEvent
from electrum_aionostr.key import PrivateKey

from electrum.util import (
    OldTaskGroup, is_valid_websocket_url, UserFacingException, InvoiceError, is_hex_str
)
from electrum import constants
from electrum.i18n import _
from electrum.invoices import PR_PAID, Invoice
from electrum.json_db import stored_in
from electrum.segwit_addr import convertbits, bech32_encode, bech32_decode, Encoding

from .escrow_worker import (
    EscrowWorker, EscrowAgentProfile, TradeContract
)
from . import constants as escrow_constants
from .constants import (
    TradePaymentDirection, TradePaymentProtocol, TradeRPC, TradeState
)
from .nostr_worker import EscrowNostrWorker
from .nostr_worker import NostrJobID

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet

@dataclasses.dataclass(kw_only=True)
class EscrowAgentInfo:
    profile_info: Optional[EscrowAgentProfile] = None
    inbound_liquidity: Optional[int] = None
    outbound_liquidity: Optional[int] = None
    relays: Optional[list[str]] = None  # todo: unused for now
    profile_ts: Optional[int] = None
    status_ts: Optional[int] = None
    relay_ts: Optional[int] = None

    def last_seen_minutes(self) -> Optional[int]:
        if self.status_ts is None:
            return None
        now = int(time.time())
        age = now - self.status_ts
        return age // 60

@stored_in('escrow_client_trades')
@dataclasses.dataclass(kw_only=True)
class ClientEscrowTrade:
    state: TradeState
    contract: TradeContract
    payment_direction: TradePaymentDirection
    payment_protocol: TradePaymentProtocol
    onchain_fallback_address: str
    escrow_agent_pubkey: str
    trade_protocol_version: int
    creation_timestamp: int = dataclasses.field(default_factory=lambda: int(time.time()))
    funding_invoice_key: Optional[str] = None
    postbox_key: Optional[str] = None
    _private_key: Optional[str] = None

    @property
    def private_key(self) -> Optional[PrivateKey]:
        if not self._private_key:
            return None
        return PrivateKey(bytes.fromhex(self._private_key))

    def __post_init__(self):
        """Needed for loading from db"""
        if type(self.state) == int:
            self.state = TradeState(self.state)
        if isinstance(self.contract, dict):
            self.contract = TradeContract(**self.contract)
        if type(self.payment_protocol) == int:
            self.payment_protocol = TradePaymentProtocol(self.payment_protocol)


@dataclasses.dataclass(frozen=True, kw_only=True)
class TradeCreationResponse:
    """Response sent by escrow agent for register_escrow"""
    trade_id: str
    funding_invoice: Invoice


class EscrowClient(EscrowWorker):

    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict):
        EscrowWorker.__init__(self, wallet, nostr_worker, storage)
        self.agent_infos = defaultdict(EscrowAgentInfo)  # type: defaultdict[str, EscrowAgentInfo]
        self.fetch_job_id = None  # type: Optional[NostrJobID]

        if 'escrow_client_trades' not in storage:
            storage['escrow_client_trades'] = {}
        self._trades = storage['escrow_client_trades']  # type: dict[str, ClientEscrowTrade]

    async def main_loop(self):
        self.logger.debug(f"escrow client started: {self.wallet.basename()}")
        async with OldTaskGroup() as g:
            tasks = (
                self._fetch_agent_events,
            )
            for task in tasks:
                await g.spawn(task())
                await asyncio.sleep(1)  # prevent rate limiting, however not as critical as we don't broadcast much

    async def _fetch_agent_events(self):
        event_kinds = [
            escrow_constants.AGENT_STATUS_EVENT_KIND,
            escrow_constants.AGENT_PROFILE_EVENT_KIND,
            escrow_constants.AGENT_RELAY_LIST_METADATA_KIND,
        ]
        event_queue = asyncio.Queue(maxsize=1000)
        while True:
            agent_pubkeys = self.storage.get('agents')
            if not agent_pubkeys:
                # If no agents are configured, wait until some are added
                await asyncio.sleep(1)
                continue

            query = {
                "kinds": event_kinds,
                "authors": agent_pubkeys,
            }
            self.fetch_job_id = self.nostr_worker.fetch_events(query, event_queue)
            while True:
                event = await event_queue.get()
                if event is None:
                    await asyncio.sleep(10)
                    break  # job got canceled, maybe proxy changed
                assert isinstance(event, nEvent)

                if event.pubkey not in self.agent_infos and event.pubkey not in agent_pubkeys:
                    self.logger.debug(f"got event for unknown pubkey: {event.pubkey=}")
                    continue

                for tag in event.tags:
                    if len(tag) >= 2 and tag[0] == 'r':
                        if tag[1] != f"net:{constants.net.NET_NAME}":
                            self.logger.debug(f"got event for different network: {tag[1]}")
                            continue

                match event.kind:
                    case escrow_constants.AGENT_PROFILE_EVENT_KIND:
                        self._handle_escrow_agent_profile(event)
                    case escrow_constants.AGENT_STATUS_EVENT_KIND:
                        self._handle_escrow_agent_status(event)
                    case escrow_constants.AGENT_RELAY_LIST_METADATA_KIND:
                        self._handle_escrow_agent_relay_list(event)
                    case _:
                        self.logger.debug(f"got unwanted nostr event kind: {event.kind}")

    def reload_agents(self):
        if self.fetch_job_id:
            # this will put none on the queue, making _fetch_agent_events create a new query
            self.nostr_worker.cancel_job(self.fetch_job_id)

    def _handle_escrow_agent_profile(self, event: nEvent):
        try:
            content = json.loads(event.content)
        except json.JSONDecodeError:
            return

        if not isinstance(content, dict):
            return

        try:
            profile = EscrowAgentProfile(**content)
        except Exception:
            self.logger.debug(f"invalid profile event: {event.id=}")
            return

        current_info = self.agent_infos.get(event.pubkey)
        if current_info:
            if event.created_at <= (current_info.profile_ts or 0):
                return

        self.agent_infos[event.pubkey].profile_info = profile
        self.agent_infos[event.pubkey].profile_ts = event.created_at

    def _handle_escrow_agent_status(self, event: nEvent):
        try:
            content = json.loads(event.content)
        except json.JSONDecodeError:
            return

        if not isinstance(content, dict):
            return

        inbound = content.get('inbound_liquidity_sat')
        if not isinstance(inbound, int):
            return

        outbound = content.get('outbound_liquidity_sat')
        if not isinstance(outbound, int):
            return

        current_info = self.agent_infos.get(event.pubkey)
        if current_info:
            if event.created_at <= (current_info.status_ts or 0):
                return

        self.agent_infos[event.pubkey].inbound_liquidity = inbound
        self.agent_infos[event.pubkey].outbound_liquidity = outbound
        self.agent_infos[event.pubkey].status_ts = event.created_at

    def _handle_escrow_agent_relay_list(self, event: nEvent):
        if (self.agent_infos[event.pubkey].relay_ts or 0) >= event.created_at:
            return
        relays = []
        for tag in event.tags:
            if len(tag) >= 2 and tag[0] == 'r' and is_valid_websocket_url(tag[1]):
                relays.append(tag[1])
        self.agent_infos[event.pubkey].relays = relays[:10]

    def get_escrow_agent_infos(self) -> Mapping[str, EscrowAgentInfo]:
        return MappingProxyType(self.agent_infos)

    def get_escrow_agents(self) -> list[str]:
        if 'agents' not in self.storage:
            self.storage['agents'] = []
        return self.storage['agents']

    def add_escrow_agent(self, agent_pubkey: str):
        agents = set(self.storage.get('agents', []))
        agents.add(agent_pubkey)
        self.storage['agents'] = list(agents)
        self.reload_agents()

    def delete_escrow_agent(self, agent_pubkey: str):
        agents = self.storage.get('agents', [])
        if agent_pubkey in agents:
            agents.remove(agent_pubkey)
            self.reload_agents()

    def get_new_privkey_for_trade(self) -> PrivateKey:
        """
        Returns a new private key to be used for the next trade.
        Key reuse can occur if trades get deleted or the user lost their db state.
        Key reuse should only affect privacy.
        """
        # todo: this doesn't seem great, however it allows to access trade keys again after losing the
        #       wallet db which is probably worth the potential privacy tradeoff?
        key_id = len(self._trades)
        privkey = self.nostr_worker.get_nostr_privkey_for_wallet(self.wallet, key_id=key_id)
        return privkey

    def save_new_trade(self, trade_id: str, trade: ClientEscrowTrade):
        assert trade_id not in self._trades, "trade already saved"
        assert trade.funding_invoice_key, "funding invoice key missing"
        invoice = self.wallet.get_invoice(trade.funding_invoice_key)
        assert isinstance(invoice, Invoice), type(invoice)
        assert self.wallet.get_invoice_status(invoice) == PR_PAID, "Funding still unpaid"
        self._trades[trade_id] = trade
        self.wallet.save_db()

    async def request_register_escrow(
        self,
        trade: ClientEscrowTrade,
    ) -> tuple[ClientEscrowTrade, TradeCreationResponse]:
        """
        Returns mutated trade and the response.
        """
        privkey = self.get_new_privkey_for_trade()

        req_payload = {
            "method": TradeRPC.REGISTER_ESCROW.value,
            "title": trade.contract.title,
            "contract": trade.contract.contract,
            "onchain_fallback_address": trade.onchain_fallback_address,
            "payment_protocol": trade.payment_protocol.value,
            "payment_network": constants.net.NET_NAME,
            "trade_protocol_version": trade.trade_protocol_version,
            "trade_amount_sat": trade.contract.trade_amount_sat,
            "bond_amount_sat": trade.contract.bond_sat,
            "contract_signature": trade.contract.sign(privkey_hex=privkey.hex()),
            "payment_direction": trade.payment_direction.value,
        }

        try:
            response = await self.nostr_worker.send_encrypted_ephemeral_message_and_await_response(
                cleartext_content=req_payload,
                recipient_pubkey=trade.escrow_agent_pubkey,
                signing_key=privkey,
                timeout_sec=30,
            )
        except TimeoutError:
            raise UserFacingException(_("Timeout while waiting for agent response."))
        except ValueError as e:
            raise UserFacingException(f"Invalid response: {str(e)}")

        error = response.get("error")
        if error is not None:
            raise UserFacingException(f"Received error from escrow agent: {error}")

        trade_id = response.get("trade_id")
        if not trade_id:
            raise UserFacingException(f"Invalid response: missing trade_id")

        if trade.payment_protocol == TradePaymentProtocol.BITCOIN_LIGHTNING:
            b11_invoice = response.get("bolt11_invoice")
            if not b11_invoice:
                raise UserFacingException(f"Invalid response: missing funding invoice")
        else:
            raise NotImplementedError("Unsupported payment protocol")

        try:
            invoice = Invoice.from_bech32(b11_invoice)
        except InvoiceError:
            raise UserFacingException(f"Invalid lightning invoice")

        if self.wallet.get_invoice(invoice.get_id()):
            raise UserFacingException(f"Got invoice we already know")

        response = TradeCreationResponse(trade_id=trade_id, funding_invoice=invoice)
        trade = dataclasses.replace(trade, funding_invoice_key=invoice.get_id(), private_key=privkey.hex())
        return trade, response

    def create_trade_postbox(self, trade_id: str) -> str:
        """
        After locking a trade the maker creates a 'postbox', the trade contract is broadcast as
        encrypted nostr event to a new, random key. The maker can then give the random private key
        to the taker out of band. The taker can fetch the contract, review it and accept it.
        """
        trade = self._trades[trade_id]
        trade_key = trade.private_key
        postbox_private_key = PrivateKey()
        assert trade_key and postbox_private_key and trade
        if trade.payment_direction == TradePaymentDirection.SENDING:
            taker_payment_direction = TradePaymentDirection.RECEIVING.value
        else:
            taker_payment_direction = TradePaymentDirection.SENDING.value
        postbox_content = {
            "contract": dataclasses.asdict(trade.contract),
            "maker_contract_sig": trade.contract.sign(privkey_hex=trade_key.hex()),
            "taker_payment_direction": taker_payment_direction,
            "escrow_agent_pubkey": trade.escrow_agent_pubkey,
            "trade_protocol_version": trade.trade_protocol_version,
            "payment_protocol": trade.payment_protocol.value,
            "payment_network": constants.net.NET_NAME,
        }
        self.nostr_worker.send_encrypted_direct_message(
            cleartext_content=postbox_content,
            recipient_pubkey=postbox_private_key.public_key.hex(),
            signing_key=trade_key,
            expiration_duration=escrow_constants.DIRECT_MESSAGE_EXPIRATION_SEC,
        )
        data5 = convertbits(
            data=postbox_private_key.raw_secret,
            frombits=8,
            tobits=5,
            pad=True,
        )
        postbox_key = bech32_encode(encoding=Encoding.BECH32, hrp='trade', data=data5)
        trade.postbox_key = postbox_key
        return postbox_key

    async def create_trade_from_postbox(self, postbox_key: str) -> Optional[ClientEscrowTrade]:
        """
        Fetches a trade postbox from nostr relays and creates a new ClientEscrowTrade for the taker.
        """
        assert postbox_key.startswith('trade')
        decoded_bech32 = bech32_decode(bech=postbox_key, ignore_long_length=True)
        if decoded_bech32.encoding is None:
            raise ValueError("Bad bech32 checksum")
        if decoded_bech32.encoding != Encoding.BECH32:
            raise ValueError("Bad bech32 encoding: must be using vanilla BECH32")
        if not decoded_bech32.hrp.startswith("trade"):
            raise ValueError("Does not start with 'trade'")
        if not decoded_bech32.data:
            return None
        postbox_privkey = PrivateKey(
            bytes(convertbits(data=decoded_bech32.data, frombits=5, tobits=8, pad=False))
        )

        query = {
            "kinds": [escrow_constants.ENCRYPTED_DIRECT_MESSAGE_KIND],
            "#p": [postbox_privkey.public_key.hex()],
            "limit": 1,
        }

        event_queue = asyncio.Queue()
        job_id = self.nostr_worker.fetch_events(query, event_queue)

        try:
            event = await asyncio.wait_for(event_queue.get(), timeout=30)
        except asyncio.TimeoutError:
            self.logger.warn("Timeout fetching postbox event")
            return None
        finally:
            self.nostr_worker.cancel_job(job_id)

        if event is None:
            self.logger.info("No postbox event found")
            return None

        assert isinstance(event, nEvent)

        try:
            content_json = postbox_privkey.decrypt_message(event.content, event.pubkey)
            content = json.loads(content_json)
            assert isinstance(content, dict), type(content)
        except Exception:
            self.logger.exception("Failed to decrypt postbox message")
            return None

        try:
            contract = TradeContract(**content['contract'])

            maker_sig = content['maker_contract_sig']
            if not contract.verify(sig_hex=maker_sig, pubkey_hex=event.pubkey):
                raise ValueError("Invalid maker signature")

            payment_direction = TradePaymentDirection(content['taker_payment_direction'])
            escrow_agent_pubkey = content['escrow_agent_pubkey']
            assert is_hex_str(escrow_agent_pubkey) and len(escrow_agent_pubkey) == 64
            trade_protocol_version = content['trade_protocol_version']
            assert isinstance(trade_protocol_version, int)
            payment_protocol = TradePaymentProtocol(content['payment_protocol'])
            if not content['payment_network'] == constants.net.NET_NAME:
                raise ValueError(f"unsupported network: {content['payment_network']}")

            onchain_fallback_address = self.wallet.get_unused_address() or self.wallet.get_receiving_address()

            trade = ClientEscrowTrade(
                state=TradeState.ONGOING,
                contract=contract,
                payment_direction=payment_direction,
                payment_protocol=payment_protocol,
                onchain_fallback_address=onchain_fallback_address,
                escrow_agent_pubkey=escrow_agent_pubkey,
                trade_protocol_version=trade_protocol_version,
            )
            # now the taker can request to accept the trade, pay the funding, then the trade can begin
            return trade

        except Exception:
            self.logger.exception("Failed to parse postbox content")
            return None
