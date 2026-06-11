import asyncio
import dataclasses
import time
import json
from collections import defaultdict
from typing import TYPE_CHECKING, Mapping, Optional

import attr

from electrum_aionostr.event import Event as nEvent
from electrum_aionostr.key import PrivateKey

from electrum.util import (
    OldTaskGroup, is_valid_websocket_url, UserFacingException, InvoiceError, is_hex_str,
    trigger_callback,
)
from electrum import constants
from electrum.i18n import _
from electrum.invoices import PR_PAID, Invoice
from electrum.stored_dict import stored_at
from electrum.segwit_addr import convertbits, bech32_encode, bech32_decode, Encoding

from .escrow_worker import (
    EscrowWorker, EscrowAgentProfile, TradeContract, NestedStoredObject,
    to_trade_state, to_trade_contract,
)
from . import constants as escrow_constants
from .constants import (
    TradePaymentDirection, TradePaymentProtocol, TradeRPC, TradeState,
    PROTOCOL_VERSION, RPC_TIMEOUT_SEC, PAYOUT_INVOICE_EXPIRY_SEC,
    SEEN_EVENT_IDS_CACHE_SIZE,
)
from .nostr_worker import EscrowNostrWorker, NostrJobID, event_matches_net, SeenEventIdCache

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


@stored_at('/plugin_data/escrow/client_data/escrow_client_trades/*')
@attr.s(kw_only=True)
class ClientEscrowTrade(NestedStoredObject):
    state = attr.ib(converter=to_trade_state)  # type: TradeState
    contract = attr.ib(converter=to_trade_contract)  # type: TradeContract
    is_maker = attr.ib(type=bool)
    onchain_fallback_address = attr.ib(type=str)
    creation_timestamp = attr.ib(type=int, default=attr.Factory(lambda: int(time.time())))
    funding_invoice_key = attr.ib(type=str, default=None)  # type: Optional[str]
    postbox_key = attr.ib(type=str, default=None)  # type: Optional[str]
    private_key_hex = attr.ib(type=str, default=None)  # type: Optional[str]
    # last known payout allocation for us, updated by state sync with the agent
    payout_due_sat = attr.ib(type=int, default=None)  # type: Optional[int]
    payout_paid = attr.ib(type=bool, default=False)

    @property
    def private_key(self) -> Optional[PrivateKey]:
        if not self.private_key_hex:
            return None
        return PrivateKey(bytes.fromhex(self.private_key_hex))

    @property
    def payment_direction(self) -> TradePaymentDirection:
        return self.contract.payment_direction(is_maker=self.is_maker)

    @property
    def escrow_agent_pubkey(self) -> str:
        return self.contract.agent_pubkey

    @property
    def funding_amount_sat(self) -> int:
        return self.contract.funding_amount_sat(self.payment_direction)


class EscrowClient(EscrowWorker):

    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict):
        EscrowWorker.__init__(self, wallet, nostr_worker, storage)
        self.agent_infos = defaultdict(EscrowAgentInfo)  # type: defaultdict[str, EscrowAgentInfo]
        self.fetch_job_id: Optional[NostrJobID] = None
        self.watch_job_id: Optional[NostrJobID] = None
        self._handled_dm_ids = SeenEventIdCache(SEEN_EVENT_IDS_CACHE_SIZE)

        if 'escrow_client_trades' not in storage:
            storage['escrow_client_trades'] = {}
        self._trades = storage['escrow_client_trades']  # type: dict[str, ClientEscrowTrade]

    async def main_loop(self):
        self.logger.debug(f"escrow client started: {self.wallet.basename()}")
        async with OldTaskGroup() as g:
            tasks = (
                self._fetch_agent_events,
                self._watch_trade_updates,
            )
            for task in tasks:
                await g.spawn(self._run_guarded(task))
                await asyncio.sleep(1)  # prevent rate limiting, however not as critical as we don't broadcast much

    def _assert_can_trade(self):
        if not self.wallet.has_lightning():
            raise UserFacingException(
                _("Your wallet doesn't support the Lightning Network. "
                  "Trading requires a wallet with Lightning support."))

    # ---------- escrow agent discovery ----------

    async def _fetch_agent_events(self):
        event_kinds = [
            escrow_constants.AGENT_STATUS_EVENT_KIND,
            escrow_constants.AGENT_PROFILE_EVENT_KIND,
            escrow_constants.AGENT_RELAY_LIST_METADATA_KIND,
        ]
        event_queue = asyncio.Queue(maxsize=1000)
        while True:
            agent_pubkeys = list(self.storage.get('agents') or [])
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
                    break  # job got canceled, maybe proxy changed or agent list updated
                assert isinstance(event, nEvent)

                if event.pubkey not in agent_pubkeys:
                    self.logger.debug(f"got event for unknown pubkey: {event.pubkey=}")
                    continue

                if not event_matches_net(event):
                    self.logger.debug(f"got event for different network: {event.id=}")
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
            profile = EscrowAgentProfile.from_remote_dict(content)
        except (json.JSONDecodeError, ValueError):
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
        if not isinstance(inbound, int) or isinstance(inbound, bool) or inbound < 0:
            return

        outbound = content.get('outbound_liquidity_sat')
        if not isinstance(outbound, int) or isinstance(outbound, bool) or outbound < 0:
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
        self.agent_infos[event.pubkey].relay_ts = event.created_at

    def get_escrow_agent_infos(self) -> Mapping[str, EscrowAgentInfo]:
        return dict(self.agent_infos)

    def get_escrow_agents(self) -> list[str]:
        if 'agents' not in self.storage:
            self.storage['agents'] = []
        return list(self.storage['agents'])

    def add_escrow_agent(self, agent_pubkey: str):
        if 'agents' not in self.storage:
            self.storage['agents'] = []
        if agent_pubkey not in self.storage['agents']:
            self.storage['agents'].append(agent_pubkey)
            self.wallet.save_db()
        self.reload_agents()

    def delete_escrow_agent(self, agent_pubkey: str):
        agents = self.storage.get('agents')
        if agents and agent_pubkey in agents:
            agents.remove(agent_pubkey)
            self.wallet.save_db()
            self.reload_agents()

    # ---------- trade state updates from the agent ----------

    @staticmethod
    def is_trade_settled(trade: 'ClientEscrowTrade') -> bool:
        """Whether nothing is left to happen for this trade (final state and any payout paid)."""
        if not trade.state.is_final():
            return False
        return trade.payout_paid or trade.payout_due_sat == 0

    def _get_watched_trades(self) -> dict[str, str]:
        """Returns {trade nostr pubkey: trade_id} of trades we want updates for."""
        watched = {}
        for trade_id, trade in self._trades.items():
            if self.is_trade_settled(trade):
                continue
            privkey = trade.private_key
            if not privkey:
                continue
            watched[privkey.public_key.hex()] = trade_id
        return watched

    async def _watch_trade_updates(self):
        """
        Watches for encrypted direct messages from agents to our trade keys (e.g. taker
        funded the trade, trade state changed) and re-syncs the trade state when one arrives.
        """
        event_queue = asyncio.Queue(maxsize=1000)
        while True:
            watched = self._get_watched_trades()
            if not watched:
                await asyncio.sleep(10)
                continue

            query = {
                "kinds": [escrow_constants.ENCRYPTED_DIRECT_MESSAGE_KIND],
                "#p": list(watched.keys()),
            }
            self.watch_job_id = self.nostr_worker.fetch_events(query, event_queue)
            while True:
                event = await event_queue.get()
                if event is None:
                    await asyncio.sleep(10)
                    break  # job got canceled (proxy change or new trade added), requery
                assert isinstance(event, nEvent)
                await self._handle_trade_update_dm(event, watched)

    async def _handle_trade_update_dm(self, event: nEvent, watched: dict[str, str]):
        if self._handled_dm_ids.seen_before(event.id):
            return
        trade_id = None
        for tag in event.tags:
            if len(tag) >= 2 and tag[0] == 'p' and tag[1] in watched:
                trade_id = watched[tag[1]]
                break
        trade = self._trades.get(trade_id)
        if trade is None:
            return
        if event.pubkey != trade.escrow_agent_pubkey:
            return  # only the agent sends us trade updates
        privkey = trade.private_key
        if not privkey:
            return
        try:
            content = json.loads(privkey.decrypt_message(event.content, event.pubkey))
            if not isinstance(content, dict):
                raise ValueError("not a dict")
            method = TradeRPC(content.get('method'))
        except Exception:
            self.logger.debug(f"could not decode trade update dm: {event.id=}")
            return
        if method not in (TradeRPC.TRADE_FUNDED, TradeRPC.TRADE_STATE_CHANGED):
            return
        self.logger.info(f"received trade update ({method.value}) for {trade_id=}")
        try:
            await self.sync_trade_state(trade_id)
        except (TimeoutError, UserFacingException) as e:
            self.logger.info(f"could not sync trade state for {trade_id=}: {e!r}")

    def reload_trade_watch(self):
        if self.watch_job_id:
            self.nostr_worker.cancel_job(self.watch_job_id)

    async def sync_trade_state(self, trade_id: str) -> dict:
        """
        Fetches the current trade state from the agent and applies it to our local trade.
        Returns the raw state info dict. Raises TimeoutError or UserFacingException.
        """
        trade = self._trades[trade_id]
        privkey = trade.private_key
        if not privkey:
            raise UserFacingException(_("Trade private key missing"))
        req_payload = {
            "method": TradeRPC.GET_TRADE_STATE.value,
            "trade_id": trade_id,
        }
        response = await self._send_rpc(trade, req_payload, privkey)
        self._apply_remote_state(trade_id, trade, response)
        return response

    def _apply_remote_state(self, trade_id: str, trade: 'ClientEscrowTrade', response: dict) -> None:
        changed = False
        state = response.get('state')
        if state is not None:
            try:
                state = TradeState(state)
            except ValueError:
                self.logger.warning(f"got invalid trade state from agent: {state!r}")
                state = None
        if state is not None and state != trade.state:
            trade.state = state
            changed = True
        payout_due = response.get('payout_due_sat')
        if (isinstance(payout_due, int) and not isinstance(payout_due, bool) and payout_due >= 0) \
                or payout_due is None:
            if 'payout_due_sat' in response and payout_due != trade.payout_due_sat:
                trade.payout_due_sat = payout_due
                changed = True
        payout_paid = response.get('payout_paid')
        if isinstance(payout_paid, bool) and payout_paid != trade.payout_paid:
            trade.payout_paid = payout_paid
            changed = True
        if changed:
            self.wallet.save_db()
            self.logger.info(f"trade {trade_id} updated: {trade.state=}")
            trigger_callback('escrow_trades_updated', self.wallet)

    # ---------- rpc helpers ----------

    async def _send_rpc(self, trade: 'ClientEscrowTrade', req_payload: dict, privkey: PrivateKey) -> dict:
        """Sends an rpc to the trade's agent. Raises UserFacingException on errors, TimeoutError on timeout."""
        try:
            response = await self.nostr_worker.send_encrypted_ephemeral_message_and_await_response(
                cleartext_content=req_payload,
                recipient_pubkey=trade.escrow_agent_pubkey,
                signing_key=privkey,
                timeout_sec=RPC_TIMEOUT_SEC,
            )
        except (TimeoutError, asyncio.TimeoutError):
            raise UserFacingException(_("Timeout while waiting for agent response. "
                                        "The agent may be offline, try again later."))
        except ValueError as e:
            raise UserFacingException(_("Invalid response: {}").format(str(e)))

        error = response.get("error")
        if error is not None:
            raise UserFacingException(_("Received error from escrow agent: {}").format(str(error)[:200]))
        return response

    def _parse_funding_invoice(self, response: dict, trade: 'ClientEscrowTrade') -> Invoice:
        """Extracts and validates the funding invoice the agent sent us."""
        if trade.contract.payment_protocol != TradePaymentProtocol.BITCOIN_LIGHTNING:
            raise NotImplementedError("Unsupported payment protocol")
        b11_invoice = response.get("bolt11_invoice")
        if not b11_invoice or not isinstance(b11_invoice, str):
            raise UserFacingException(_("Invalid response: missing funding invoice"))
        try:
            invoice = Invoice.from_bech32(b11_invoice)
        except InvoiceError:
            raise UserFacingException(_("Invalid lightning invoice"))
        if self.wallet.get_invoice(invoice.get_id()):
            raise UserFacingException(_("Got an invoice we already know"))
        amount = invoice.get_amount_sat()
        expected = trade.funding_amount_sat
        if not isinstance(amount, int) or amount != expected:
            raise UserFacingException(
                _("Agent sent a funding invoice over {} sat but {} sat were expected.")
                .format(amount, expected))
        if invoice.has_expired():
            raise UserFacingException(_("Agent sent an expired funding invoice"))
        return invoice

    def _create_payout_invoice(self, amount_sat: int, message: str) -> str:
        """Creates a bolt11 payment request the agent can pay us. Raises UserFacingException."""
        self._assert_can_trade()
        if amount_sat <= 0:
            raise UserFacingException(_("Nothing to pay out"))
        can_receive = int(self.wallet.lnworker.num_sats_can_receive() or 0)
        if can_receive < amount_sat:
            raise UserFacingException(
                _("You cannot receive the payout of {} sat with your Lightning channels. "
                  "Please increase your incoming liquidity, e.g. with a submarine swap in the "
                  "Channels tab.").format(amount_sat))
        req_key = self.wallet.create_request(
            amount_sat=amount_sat,
            message=message,
            exp_delay=PAYOUT_INVOICE_EXPIRY_SEC,
            address=None,
        )
        req = self.wallet.get_request(req_key)
        bolt11 = self.wallet.get_bolt11_invoice(req)
        if not bolt11:
            raise UserFacingException(_("Could not create lightning invoice"))
        return bolt11

    # ---------- trade lifecycle (requests to the agent) ----------

    def get_trades(self) -> dict[str, ClientEscrowTrade]:
        return dict(self._trades)

    def get_trade(self, trade_id: str) -> Optional[ClientEscrowTrade]:
        return self._trades.get(trade_id)

    def get_new_privkey_for_trade(self) -> PrivateKey:
        """
        Returns a new private key to be used for the next trade.
        Uses a persistent counter so keys are never reused, even for abandoned trades.
        """
        key_id = self.storage.get('trade_key_counter', 0)
        self.storage['trade_key_counter'] = key_id + 1
        self.wallet.save_db()
        privkey = self.get_nostr_privkey_for_wallet(self.wallet, key_id=key_id)
        return privkey

    def save_new_trade(self, trade_id: str, trade: ClientEscrowTrade):
        assert trade_id not in self._trades, "trade already saved"
        if trade.funding_amount_sat > 0:
            assert trade.funding_invoice_key, "funding invoice key missing"
            invoice = self.wallet.get_invoice(trade.funding_invoice_key)
            assert isinstance(invoice, Invoice), type(invoice)
            assert self.wallet.get_invoice_status(invoice) == PR_PAID, "Funding still unpaid"
        self._trades[trade_id] = trade
        self.wallet.save_db()
        self.reload_trade_watch()
        trigger_callback('escrow_trades_updated', self.wallet)

    async def request_register_escrow(self, trade: ClientEscrowTrade) -> tuple[str, Optional[Invoice]]:
        """
        Maker registers the trade with the agent. Sets the trade key and funding invoice
        on the trade and returns (trade_id, funding invoice). The invoice is None if there
        is nothing to pay from the maker side (e.g. zero bond).
        """
        self._assert_can_trade()
        privkey = self.get_new_privkey_for_trade()

        req_payload = {
            "method": TradeRPC.REGISTER_ESCROW.value,
            "contract": trade.contract.to_json(),
            "contract_signature": trade.contract.sign(privkey_hex=privkey.hex()),
            "onchain_fallback_address": trade.onchain_fallback_address,
            "payment_network": constants.net.NET_NAME,
            "trade_protocol_version": PROTOCOL_VERSION,
        }

        response = await self._send_rpc(trade, req_payload, privkey)

        trade_id = response.get("trade_id")
        if not trade_id or not is_hex_str(trade_id) or len(trade_id) > 128:
            raise UserFacingException(_("Invalid response: missing trade_id"))

        invoice = None
        if trade.funding_amount_sat > 0:
            invoice = self._parse_funding_invoice(response, trade)
            trade.funding_invoice_key = invoice.get_id()
        trade.private_key_hex = privkey.hex()
        return trade_id, invoice

    async def request_accept_escrow(self, trade: ClientEscrowTrade, trade_id: str) -> Optional[Invoice]:
        """
        Taker accepts a maker's trade. Sets the trade key and funding invoice on the trade
        and returns the funding invoice. The invoice is None if there is nothing to pay
        from the taker side (e.g. zero bond).
        """
        self._assert_can_trade()
        privkey = self.get_new_privkey_for_trade()

        req_payload = {
            "method": TradeRPC.ACCEPT_ESCROW.value,
            "trade_id": trade_id,
            "contract_signature": trade.contract.sign(privkey_hex=privkey.hex()),
            "onchain_fallback_address": trade.onchain_fallback_address,
        }

        response = await self._send_rpc(trade, req_payload, privkey)

        invoice = None
        if trade.funding_amount_sat > 0:
            invoice = self._parse_funding_invoice(response, trade)
            trade.funding_invoice_key = invoice.get_id()
        trade.private_key_hex = privkey.hex()
        return invoice

    async def request_collaborative_confirm(self, trade_id: str):
        """
        Signals the agent that from our side the trade was completed successfully.
        Once both parties have confirmed, the agent pays out.
        """
        trade = self._trades[trade_id]
        privkey = trade.private_key
        if not privkey:
            raise UserFacingException(_("Trade private key missing"))

        payout_invoice = None
        if trade.payment_direction == TradePaymentDirection.RECEIVING:
            payout_amount = trade.contract.payout_amount_sat()
            payout_invoice = self._create_payout_invoice(
                payout_amount, f"Escrow payout: {trade.contract.title}")

        req_payload = {
            "method": TradeRPC.COLLABORATIVE_CONFIRM.value,
            "trade_id": trade_id,
            "payout_invoice": payout_invoice,
        }
        response = await self._send_rpc(trade, req_payload, privkey)
        self._apply_remote_state(trade_id, trade, response)

    async def request_collaborative_cancel(self, trade_id: str):
        """
        Requests to cancel the trade. While the trade has no funded taker the maker can
        cancel unilaterally; afterwards both parties have to request cancellation.
        Everyone gets back what they paid.
        """
        trade = self._trades[trade_id]
        privkey = trade.private_key
        if not privkey:
            raise UserFacingException(_("Trade private key missing"))

        refund_amount = trade.funding_amount_sat
        payout_invoice = None
        if refund_amount > 0:
            payout_invoice = self._create_payout_invoice(
                refund_amount, f"Escrow refund: {trade.contract.title}")

        req_payload = {
            "method": TradeRPC.COLLABORATIVE_CANCEL.value,
            "trade_id": trade_id,
            "payout_invoice": payout_invoice,
        }
        response = await self._send_rpc(trade, req_payload, privkey)
        self._apply_remote_state(trade_id, trade, response)

    async def request_mediation(self, trade_id: str):
        """
        Unilaterally puts the trade into mediation. The participants then have to contact
        the agent out of band (see agent profile) so the agent can decide the outcome.
        """
        trade = self._trades[trade_id]
        privkey = trade.private_key
        if not privkey:
            raise UserFacingException(_("Trade private key missing"))
        req_payload = {
            "method": TradeRPC.REQUEST_MEDIATION.value,
            "trade_id": trade_id,
        }
        response = await self._send_rpc(trade, req_payload, privkey)
        self._apply_remote_state(trade_id, trade, response)

    async def request_claim_payout(self, trade_id: str):
        """
        Submits a fresh payout invoice for our outstanding allocation, e.g. after mediation,
        after a missed automatic payout, or when our original payout invoice expired.
        """
        trade = self._trades[trade_id]
        privkey = trade.private_key
        if not privkey:
            raise UserFacingException(_("Trade private key missing"))

        # refresh the allocation first
        await self.sync_trade_state(trade_id)
        if trade.payout_paid:
            raise UserFacingException(_("The payout was already paid."))
        due = trade.payout_due_sat
        if not due:
            raise UserFacingException(_("There is no payout to claim for this trade."))

        payout_invoice = self._create_payout_invoice(
            due, f"Escrow payout: {trade.contract.title}")
        req_payload = {
            "method": TradeRPC.CLAIM_PAYOUT.value,
            "trade_id": trade_id,
            "payout_invoice": payout_invoice,
        }
        response = await self._send_rpc(trade, req_payload, privkey)
        self._apply_remote_state(trade_id, trade, response)

    # ---------- trade postbox (sharing a trade with the taker) ----------

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
        postbox_content = {
            "trade_id": trade_id,
            "contract": trade.contract.to_json(),
            "maker_contract_sig": trade.contract.sign(privkey_hex=trade_key.hex()),
            # net and version are also committed to by the contract signature, the
            # cleartext fields just allow friendly error messages
            "trade_protocol_version": PROTOCOL_VERSION,
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
        self.wallet.save_db()
        return postbox_key

    async def create_trade_from_postbox(self, postbox_key: str) -> Optional[tuple[ClientEscrowTrade, str]]:
        """
        Fetches a trade postbox from nostr relays and creates a new (unsaved) ClientEscrowTrade
        for the taker. Returns None if no postbox was found, raises ValueError on bad
        postbox keys and UserFacingException on invalid postbox contents.
        """
        self._assert_can_trade()
        postbox_key = postbox_key.strip()
        if not postbox_key.startswith('trade'):
            raise ValueError(_("Does not start with 'trade'"))
        decoded_bech32 = bech32_decode(bech=postbox_key, ignore_long_length=True)
        if decoded_bech32.encoding is None:
            raise ValueError(_("Bad bech32 checksum"))
        if decoded_bech32.encoding != Encoding.BECH32:
            raise ValueError(_("Bad bech32 encoding: must be using vanilla BECH32"))
        if not decoded_bech32.data:
            return None
        privkey_bytes = convertbits(data=decoded_bech32.data, frombits=5, tobits=8, pad=False)
        if not privkey_bytes or len(privkey_bytes) != 32:
            raise ValueError(_("Invalid postbox key length"))
        postbox_privkey = PrivateKey(bytes(privkey_bytes))

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
            self.logger.warning("Timeout fetching postbox event")
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
            raise UserFacingException(_("Could not decrypt the trade postbox."))

        try:
            # now the taker can request to accept the trade, pay the funding, then the trade can begin
            return self._parse_postbox_content(content, maker_pubkey=event.pubkey)
        except ValueError as e:
            self.logger.info(f"Failed to parse postbox content: {e!r}")
            raise UserFacingException(str(e))
        except Exception:
            self.logger.exception("Failed to parse postbox content")
            raise UserFacingException(_("The trade postbox contents are invalid."))

    def _parse_postbox_content(self, content: dict, *, maker_pubkey: str) -> tuple[ClientEscrowTrade, str]:
        """Validates postbox contents and builds the taker-side trade.
        Raises ValueError on invalid contents."""
        # friendly checks first; these are also committed to by the contract signature
        if content.get('payment_network') != constants.net.NET_NAME:
            raise ValueError(_("Trade is for a different network: {}")
                             .format(str(content.get('payment_network'))[:20]))
        if content.get('trade_protocol_version') != PROTOCOL_VERSION:
            raise ValueError(_("Trade was created with an incompatible plugin version."))

        contract = TradeContract.from_remote_dict(content.get('contract'))
        if contract.payment_protocol not in escrow_constants.SUPPORTED_PAYMENT_PROTOCOLS:
            raise ValueError(_("Unsupported payment protocol"))

        maker_sig = content.get('maker_contract_sig')
        if not isinstance(maker_sig, str) or not contract.verify(sig_hex=maker_sig, pubkey_hex=maker_pubkey):
            raise ValueError(_("Invalid maker signature"))

        trade_id = content.get('trade_id')
        if not trade_id or not is_hex_str(trade_id) or len(trade_id) > 128:
            raise ValueError(_("Missing trade_id in postbox"))
        if trade_id in self._trades:
            raise ValueError(_("You already have this trade."))

        onchain_fallback_address = self.wallet.get_unused_address() or self.wallet.get_receiving_address()

        trade = ClientEscrowTrade(
            state=TradeState.ONGOING,
            contract=contract,
            is_maker=False,
            onchain_fallback_address=onchain_fallback_address,
        )
        return trade, trade_id
