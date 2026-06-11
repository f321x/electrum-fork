import time
import json
import secrets
import dataclasses
from typing import TYPE_CHECKING, Optional
import asyncio

import attr

from electrum_aionostr.event import Event as nEvent

from electrum import constants
from electrum.util import OldTaskGroup, InvoiceError, EventListener, event_listener, trigger_callback
from electrum.invoices import Invoice, PR_PAID
from electrum.bitcoin import is_address
from electrum.stored_dict import stored_at

from .escrow_worker import (
    EscrowWorker, EscrowAgentProfile, TradeContract, NestedStoredObject,
    to_trade_state, to_trade_contract,
)
from .constants import (
    STATUS_EVENT_INTERVAL_SEC, PROFILE_EVENT_INTERVAL_SEC, RELAY_EVENT_INTERVAL_SEC,
    DIRECT_MESSAGE_EXPIRATION_SEC, PAYOUT_TIMEOUT_SEC, PAYOUT_INTERVAL_SEC,
    MAX_AMOUNT_PENDING_TRADES, SUPPORTED_PAYMENT_PROTOCOLS, PROTOCOL_VERSION,
    FUNDING_INVOICE_EXPIRY_SEC, SEEN_EVENT_IDS_CACHE_SIZE,
    TradeState, TradeRPC, TradePaymentDirection,
    EPHEMERAL_REQUEST_EVENT_KIND,
)
from .nostr_worker import get_net_tag, get_protocol_tag, SeenEventIdCache

if TYPE_CHECKING:
    from .nostr_worker import EscrowNostrWorker
    from electrum.wallet import Abstract_Wallet


def _to_participant(v) -> Optional['TradeParticipant']:
    if isinstance(v, dict):
        return TradeParticipant(**v)
    return v


@attr.s(kw_only=True)
class TradeParticipant(NestedStoredObject):
    pubkey = attr.ib(type=str)
    # key of our payment request the participant funds the trade with, None if nothing to pay
    funding_request_key = attr.ib(type=str, default=None)  # type: Optional[str]
    onchain_fallback_address = attr.ib(type=str, default=None)  # type: Optional[str]
    contract_signature = attr.ib(type=str, default=None)  # signature over the contract hash
    confirmed = attr.ib(type=bool, default=False)
    cancel_requested = attr.ib(type=bool, default=False)
    # timestamp of the participant's last confirm/cancel vote, so a misbehaving relay
    # cannot flip a vote back by replaying an older request event
    last_action_ts = attr.ib(type=int, default=0)
    # candidate payout invoice submitted by the participant (validated when registered)
    payout_invoice = attr.ib(type=str, default=None)  # type: Optional[str]
    # what we owe this participant, set when the trade gets finalized
    payout_due_sat = attr.ib(type=int, default=None)  # type: Optional[int]
    # wallet key of the payout invoice we registered for payment
    payout_invoice_key = attr.ib(type=str, default=None)  # type: Optional[str]
    payout_paid = attr.ib(type=bool, default=False)


@attr.s(kw_only=True)
class TradeParticipants(NestedStoredObject):
    maker = attr.ib(converter=_to_participant)  # type: TradeParticipant
    taker = attr.ib(converter=_to_participant, default=None)  # type: Optional[TradeParticipant]

    def both(self) -> list[TradeParticipant]:
        return [p for p in (self.maker, self.taker) if p is not None]


@stored_at('/plugin_data/escrow/agent_data/escrow_agent_trades/*')
@attr.s(kw_only=True)
class AgentEscrowTrade(NestedStoredObject):
    state = attr.ib(converter=to_trade_state)  # type: TradeState
    trade_participants = attr.ib(converter=lambda v: TradeParticipants(**v) if isinstance(v, dict) else v)  # type: TradeParticipants
    contract = attr.ib(converter=to_trade_contract)  # type: TradeContract
    creation_timestamp = attr.ib(type=int, default=attr.Factory(lambda: int(time.time())))

    def participant_for_pubkey(self, pubkey: str) -> Optional[TradeParticipant]:
        participants = self.trade_participants
        if pubkey == participants.maker.pubkey:
            return participants.maker
        if participants.taker and pubkey == participants.taker.pubkey:
            return participants.taker
        return None

    def is_maker(self, participant: TradeParticipant) -> bool:
        return participant is self.trade_participants.maker

    def payment_direction_of(self, participant: TradeParticipant) -> TradePaymentDirection:
        return self.contract.payment_direction(is_maker=self.is_maker(participant))

    def receiver_participant(self) -> Optional[TradeParticipant]:
        """The participant receiving the main trade payment (and paying the bond)."""
        if self.contract.maker_payment_direction == TradePaymentDirection.RECEIVING:
            return self.trade_participants.maker
        return self.trade_participants.taker


class EscrowAgent(EscrowWorker, EventListener):

    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict):
        EscrowWorker.__init__(self, wallet, nostr_worker, storage)
        assert wallet.has_lightning(), "Wallet needs lightning support"

        # wallet invoice key -> next payment attempt ts
        if 'pending_lightning_invoices' not in storage:
            storage['pending_lightning_invoices'] = {}
        self._lightning_invoices_to_pay = storage['pending_lightning_invoices']  # type: dict[str, int]
        self._payments_in_flight = set()  # type: set[str]

        # we derive a persistent nostr identity from the wallet
        self.nostr_identity_private_key = self.get_nostr_privkey_for_wallet(wallet)

        if 'escrow_agent_trades' not in storage:
            storage['escrow_agent_trades'] = {}
        self._trades = storage['escrow_agent_trades']  # type: dict[str, AgentEscrowTrade]

        # newly registered trades, waiting for the maker to send us the funds. We only persist the
        # trade once the invoice is paid to avoid writing every request to the db.
        self._pending_trades = {}  # type: dict[str, AgentEscrowTrade]

        # replay protection against misbehaving relays re-serving ephemeral request events
        self._seen_request_ids = SeenEventIdCache(SEEN_EVENT_IDS_CACHE_SIZE)

        self.register_callbacks()

    async def main_loop(self):
        self.logger.debug(f"escrow agent started: {self.wallet.basename()}")
        tasks = (
            self._broadcast_status_event,
            self._maybe_rebroadcast_profile_event,
            self._broadcast_relay_event,
            self._handle_requests,
            self._pay_pending_lightning_invoices,
            self._cleanup_expired_funding_requests,
        )
        async with OldTaskGroup() as g:
            for task in tasks:
                await g.spawn(self._run_guarded(task))
                await asyncio.sleep(3)  # prevent getting rate limited by relays

    def get_trades(self) -> dict[str, AgentEscrowTrade]:
        return dict(self._trades)

    def get_identity_pubkey(self) -> str:
        return self.nostr_identity_private_key.public_key.hex()

    def stop(self):
        self._cleanup_pending_trades()
        self.unregister_callbacks()
        EscrowWorker.stop(self)

    # ---------- funding detection ----------

    @event_listener
    def on_event_request_status(self, wallet: 'Abstract_Wallet', key: str, status: int):
        if wallet != self.wallet:
            return
        if status != PR_PAID:
            return
        # check if the payment was for a pending trade. Move pending trade to active trades.
        for trade_id, trade in list(self._pending_trades.items()):
            if trade.trade_participants.maker.funding_request_key == key:
                self._handle_maker_funding(trade_id)
                return
        for trade_id, trade in self._trades.items():
            taker = trade.trade_participants.taker
            if taker and taker.funding_request_key == key:
                self._handle_taker_funding(trade_id)
                return

    def _handle_maker_funding(self, trade_id: str):
        """Maker has paid their funding invoice. Now the trade can get persisted in the db."""
        if trade_id in self._trades:
            return
        self._trades[trade_id] = self._pending_trades.pop(trade_id)
        self.wallet.save_db()
        trigger_callback('escrow_trades_updated', self.wallet)
        self.logger.info(f"maker funding received: {trade_id=}")

    def _handle_taker_funding(self, trade_id: str):
        """Taker has paid their funding invoice. Maker must already have paid before."""
        trade = self._trades[trade_id]
        if trade.state != TradeState.WAITING_FOR_TAKER:
            self.logger.warning(f"got taker funding for trade in state {trade.state}: {trade_id=}")
            return
        trade.state = TradeState.ONGOING
        self.wallet.save_db()
        trigger_callback('escrow_trades_updated', self.wallet)
        self.logger.info(f"taker funding received: {trade_id=}")
        self._notify_participant(trade.trade_participants.maker, TradeRPC.TRADE_FUNDED, trade_id)

    def _notify_participant(self, participant: Optional[TradeParticipant], method: TradeRPC, trade_id: str):
        """
        Notifies a participant about a trade event with an encrypted dm.
        The event can't be ephemeral as the participant might not be online to receive it,
        so we set an expiration of DIRECT_MESSAGE_EXPIRATION_SEC which should be longer
        than any sane trade duration.
        """
        if participant is None:
            return
        msg = {
            "method": method.value,
            "trade_id": trade_id,
        }
        self.nostr_worker.send_encrypted_direct_message(
            cleartext_content=msg,
            recipient_pubkey=participant.pubkey,
            expiration_duration=DIRECT_MESSAGE_EXPIRATION_SEC,
            signing_key=self.nostr_identity_private_key,
        )

    # ---------- pending (unfunded) trade management ----------

    def _add_new_trade(self, trade: AgentEscrowTrade) -> str:
        """
        Evicts oldest unfunded trade if MAX_AMOUNT_PENDING_TRADES is exceeded.
        Returns new trade id.
        """
        if len(self._pending_trades) >= MAX_AMOUNT_PENDING_TRADES:
            oldest_key = min(self._pending_trades, key=lambda k: self._pending_trades[k].creation_timestamp)
            funding_request_key = self._pending_trades[oldest_key].trade_participants.maker.funding_request_key
            if funding_request_key:
                self.wallet.delete_request(funding_request_key)
            del self._pending_trades[oldest_key]
        trade_id = secrets.token_hex(32)
        self._pending_trades[trade_id] = trade
        return trade_id

    def _cleanup_pending_trades(self):
        """
        Called on shutdown to delete all unfunded trades and their payment requests.
        This is done to prevent funding requests from getting paid after restart when we have
        no associated trade for it anymore.
        """
        for trade in self._pending_trades.values():
            funding_request_key = trade.trade_participants.maker.funding_request_key
            if funding_request_key:
                self.wallet.delete_request(funding_request_key)
        self._pending_trades.clear()

    def _is_funding_request_expired(self, funding_request_key: Optional[str]) -> bool:
        """Whether an unpaid funding request can be considered dead."""
        if not funding_request_key:
            return False  # nothing was to be paid
        req = self.wallet.get_request(funding_request_key)
        if req is None:
            return True
        if self.wallet.get_invoice_status(req) == PR_PAID:
            return False  # paid, the payment event is or was processed
        return req.has_expired()

    def _clear_taker_slot(self, trade: AgentEscrowTrade):
        taker = trade.trade_participants.taker
        if taker is None:
            return
        if taker.funding_request_key:
            self.wallet.delete_request(taker.funding_request_key)
        trade.trade_participants.taker = None
        self.wallet.save_db()

    async def _cleanup_expired_funding_requests(self):
        """
        Deletes pending trades for which the maker funding invoice expired unpaid, and
        frees taker slots of takers that accepted but never paid, so another taker
        (or the same one) can accept the trade again.
        """
        while True:
            await asyncio.sleep(30)
            for trade_id, trade in list(self._pending_trades.items()):
                key = trade.trade_participants.maker.funding_request_key
                if self._is_funding_request_expired(key):
                    if key:
                        self.wallet.delete_request(key)
                    self._pending_trades.pop(trade_id, None)
            for trade_id, trade in list(self._trades.items()):
                if trade.state != TradeState.WAITING_FOR_TAKER:
                    continue
                taker = trade.trade_participants.taker
                if taker and self._is_funding_request_expired(taker.funding_request_key):
                    self.logger.info(f"taker never funded, freeing taker slot: {trade_id=}")
                    self._clear_taker_slot(trade)

    # ---------- request handling ----------

    async def _handle_requests(self):
        query = {
            "kinds": [EPHEMERAL_REQUEST_EVENT_KIND],
            "#p": [self.get_identity_pubkey()],
            "#r": [get_net_tag()[1]],
            "#d": [get_protocol_tag()[1]],
            "limit": 0,
        }
        privkey = self.nostr_identity_private_key
        event_queue = asyncio.Queue(maxsize=1000)
        while True:
            self.nostr_worker.fetch_events(query, event_queue)
            while True:
                event = await event_queue.get()
                if event is None:
                    await asyncio.sleep(10)  # query job got canceled, maybe proxy changed
                    break
                await asyncio.sleep(0.1)  # soft rate limit
                assert isinstance(event, nEvent)
                if self._seen_request_ids.seen_before(event.id):
                    continue
                pubkey = event.pubkey
                try:
                    content = privkey.decrypt_message(event.content, pubkey)
                    content = json.loads(content)
                    if not isinstance(content, dict):
                        raise Exception("malformed content, not dict")
                except Exception:
                    continue

                try:
                    method = TradeRPC(content.get('method'))
                except ValueError:
                    continue

                try:
                    match method:
                        case TradeRPC.REGISTER_ESCROW:
                            self._handle_register_escrow(content, pubkey, event.id)
                        case TradeRPC.ACCEPT_ESCROW:
                            self._handle_accept_escrow(content, pubkey, event.id)
                        case TradeRPC.COLLABORATIVE_CONFIRM:
                            self._handle_collaborative_confirm(
                                content, pubkey, event.id, event_created_at=event.created_at)
                        case TradeRPC.COLLABORATIVE_CANCEL:
                            self._handle_collaborative_cancel(
                                content, pubkey, event.id, event_created_at=event.created_at)
                        case TradeRPC.REQUEST_MEDIATION:
                            self._handle_request_mediation(content, pubkey, event.id)
                        case TradeRPC.GET_TRADE_STATE:
                            self._handle_get_trade_state(content, pubkey, event.id)
                        case TradeRPC.CLAIM_PAYOUT:
                            self._handle_claim_payout(content, pubkey, event.id)
                        case _:
                            continue  # notification methods, not requests
                except Exception:
                    # handlers do their own error responses; this is a safety net so a
                    # crashing handler doesn't take down request processing
                    self.logger.exception(f"unexpected error handling {method.value} request")

    def _respond(self, *, content: dict, recipient_pubkey: str, request_event_id: str):
        self.nostr_worker.send_encrypted_ephemeral_message(
            cleartext_content=content,
            recipient_pubkey=recipient_pubkey,
            signing_key=self.nostr_identity_private_key,
            response_to_id=request_event_id,
        )

    def _respond_error(self, error: str, recipient_pubkey: str, request_event_id: str):
        self._respond(
            content={"error": error},
            recipient_pubkey=recipient_pubkey,
            request_event_id=request_event_id,
        )

    def _trade_state_response(self, trade: AgentEscrowTrade, participant: TradeParticipant) -> dict:
        participants = trade.trade_participants
        return {
            "status": "ok",
            "state": int(trade.state),
            "taker_present": participants.taker is not None,
            "maker_confirmed": participants.maker.confirmed,
            "taker_confirmed": bool(participants.taker and participants.taker.confirmed),
            "maker_cancel_requested": participants.maker.cancel_requested,
            "taker_cancel_requested": bool(participants.taker and participants.taker.cancel_requested),
            "payout_due_sat": participant.payout_due_sat,
            "payout_paid": participant.payout_paid,
        }

    def _get_trade_and_participant(self, request: dict, sender_pubkey: str) -> tuple[str, AgentEscrowTrade, TradeParticipant]:
        """Authenticates a request against an existing trade. Raises ValueError."""
        trade_id = request.get("trade_id")
        if not trade_id or not isinstance(trade_id, str):
            raise ValueError("missing trade_id")
        trade = self._trades.get(trade_id)
        if not trade:
            raise ValueError("trade not found")
        participant = trade.participant_for_pubkey(sender_pubkey)
        if participant is None:
            raise ValueError("sender is not a participant")
        return trade_id, trade, participant

    # ---------- trade registration ----------

    def _check_inbound_liquidity(self, amount_sat: int):
        can_receive = int(self.wallet.lnworker.num_sats_can_receive() or 0)
        if can_receive < amount_sat:
            raise ValueError("agent has insufficient inbound liquidity for the funding payment, "
                             "try a smaller amount or contact the agent")

    def _create_funding_request(self, amount_sat: int, title: str) -> tuple[Optional[str], Optional[str]]:
        """Returns (request key, bolt11 invoice), or (None, None) if there is nothing to pay."""
        if amount_sat == 0:
            return None, None
        self._check_inbound_liquidity(amount_sat)
        req_key = self.wallet.create_request(
            amount_sat=amount_sat,
            message=f"Escrow funding: {title}",
            exp_delay=FUNDING_INVOICE_EXPIRY_SEC,
            address=None,
        )
        req = self.wallet.get_request(req_key)
        bolt11 = self.wallet.get_bolt11_invoice(req)
        if not bolt11:
            self.wallet.delete_request(req_key)
            raise ValueError("agent could not create funding invoice")
        return req_key, bolt11

    def _handle_register_escrow(self, request: dict, sender_pubkey: str, request_event_id: str):
        """
        The maker client calls this to register a new escrow contract.
        """
        try:
            # friendly checks, these are also committed to by the contract hash
            if request.get("payment_network") != constants.net.NET_NAME:
                raise ValueError("invalid payment_network")
            if request.get("trade_protocol_version") != PROTOCOL_VERSION:
                raise ValueError(f"unsupported trade_protocol_version, agent uses {PROTOCOL_VERSION}")

            contract = TradeContract.from_remote_dict(request.get("contract"))

            if contract.agent_pubkey != self.get_identity_pubkey():
                raise ValueError("contract is addressed to a different agent")
            if contract.payment_protocol not in SUPPORTED_PAYMENT_PROTOCOLS:
                raise ValueError("unsupported payment_protocol")

            profile = self.get_profile()
            if profile is None:
                raise ValueError("agent is not configured yet")
            if contract.agent_fee_ppm != profile.service_fee_ppm:
                raise ValueError(f"agent fee mismatch, agent charges {profile.service_fee_ppm} ppm")

            signature = request.get('contract_signature')
            if not signature or not contract.verify(sig_hex=signature, pubkey_hex=sender_pubkey):
                raise ValueError("invalid contract_signature")

            onchain_fallback_address = request.get("onchain_fallback_address")
            if not onchain_fallback_address or not is_address(onchain_fallback_address):
                raise ValueError("invalid onchain fallback address")

            funding_sat = contract.funding_amount_sat(contract.maker_payment_direction)
            req_key, bolt11 = self._create_funding_request(funding_sat, contract.title)

            maker = TradeParticipant(
                pubkey=sender_pubkey,
                funding_request_key=req_key,
                onchain_fallback_address=onchain_fallback_address,
                contract_signature=signature,
            )

            trade = AgentEscrowTrade(
                state=TradeState.WAITING_FOR_TAKER,
                trade_participants=TradeParticipants(maker=maker),
                contract=contract,
            )

            if funding_sat == 0:
                # nothing to pay, the trade is funded from the maker side right away
                trade_id = secrets.token_hex(32)
                self._trades[trade_id] = trade
                self.wallet.save_db()
                trigger_callback('escrow_trades_updated', self.wallet)
            else:
                trade_id = self._add_new_trade(trade)

            response = {
                "trade_id": trade_id,
                "bolt11_invoice": bolt11,
            }
            self._respond(content=response, recipient_pubkey=sender_pubkey, request_event_id=request_event_id)
            self.logger.info(f"Registered new trade {trade_id} for {sender_pubkey}")
        except (ValueError, InvoiceError) as e:
            self.logger.info(f"Failed to register escrow: {e!r}")
            self._respond_error(str(e), sender_pubkey, request_event_id)
        except Exception:
            self.logger.exception("Failed to register escrow")
            self._respond_error("internal error", sender_pubkey, request_event_id)

    def _handle_accept_escrow(self, request: dict, sender_pubkey: str, request_event_id: str):
        """
        Sent by taker to accept an escrow contract the maker has previously registered.
        """
        try:
            trade_id = request.get("trade_id")
            if not trade_id or not isinstance(trade_id, str):
                raise ValueError("missing trade_id")

            trade = self._trades.get(trade_id)
            if not trade:
                raise ValueError("trade not found")

            if trade.state != TradeState.WAITING_FOR_TAKER:
                raise ValueError(f"trade not in waiting state: {trade.state.name}")

            if sender_pubkey == trade.trade_participants.maker.pubkey:
                raise ValueError("maker cannot take their own trade")

            existing_taker = trade.trade_participants.taker
            if existing_taker:
                # free the slot if the previous taker never funded and their invoice expired
                if self._is_funding_request_expired(existing_taker.funding_request_key):
                    self._clear_taker_slot(trade)
                else:
                    raise ValueError("taker already registered")

            signature = request.get('contract_signature')
            if not signature or not trade.contract.verify(sig_hex=signature, pubkey_hex=sender_pubkey):
                raise ValueError("invalid contract_signature")

            onchain_fallback_address = request.get("onchain_fallback_address")
            if not onchain_fallback_address or not is_address(onchain_fallback_address):
                raise ValueError("invalid onchain fallback address")

            taker_direction = trade.contract.maker_payment_direction.inverted()
            funding_sat = trade.contract.funding_amount_sat(taker_direction)
            req_key, bolt11 = self._create_funding_request(funding_sat, trade.contract.title)

            taker = TradeParticipant(
                pubkey=sender_pubkey,
                funding_request_key=req_key,
                onchain_fallback_address=onchain_fallback_address,
                contract_signature=signature,
            )
            trade.trade_participants.taker = taker

            if funding_sat == 0:
                # nothing to pay from the taker side, the trade is live right away
                trade.state = TradeState.ONGOING
                self._notify_participant(trade.trade_participants.maker, TradeRPC.TRADE_FUNDED, trade_id)

            self.wallet.save_db()
            trigger_callback('escrow_trades_updated', self.wallet)

            response = {
                "trade_id": trade_id,
                "bolt11_invoice": bolt11,
            }
            self._respond(content=response, recipient_pubkey=sender_pubkey, request_event_id=request_event_id)
            self.logger.info(f"Accepted trade {trade_id} by {sender_pubkey}")

        except (ValueError, InvoiceError) as e:
            self.logger.info(f"Failed to accept escrow: {e!r}")
            self._respond_error(str(e), sender_pubkey, request_event_id)
        except Exception:
            self.logger.exception("Failed to accept escrow")
            self._respond_error("internal error", sender_pubkey, request_event_id)

    # ---------- trade resolution ----------

    def _validate_payout_invoice(self, b11_invoice, expected_amount_sat: int) -> Optional[Invoice]:
        """Returns the parsed invoice if it is usable for the expected payout, else None."""
        if not b11_invoice or not isinstance(b11_invoice, str) or expected_amount_sat <= 0:
            return None
        try:
            invoice = Invoice.from_bech32(b11_invoice)
        except InvoiceError:
            return None
        amount = invoice.get_amount_sat()
        if not isinstance(amount, int) or amount != expected_amount_sat:
            return None
        if invoice.has_expired():
            return None
        return invoice

    def _projected_payout_sat(self, trade: AgentEscrowTrade, participant: TradeParticipant,
                              final_state: TradeState) -> int:
        """What the participant would be owed if the trade ended in final_state now."""
        if final_state == TradeState.FINISHED:
            if participant is trade.receiver_participant():
                return trade.contract.payout_amount_sat()
            return 0
        elif final_state == TradeState.CANCELLED:
            # everyone gets back what they paid
            return trade.contract.funding_amount_sat(trade.payment_direction_of(participant))
        raise ValueError(f"not a final state: {final_state}")

    def _store_candidate_payout_invoice(self, trade: AgentEscrowTrade, participant: TradeParticipant,
                                        b11_invoice, final_state: TradeState) -> bool:
        """Stores a payout invoice candidate for the assumed trade outcome.
        Returns whether the invoice was accepted."""
        expected = self._projected_payout_sat(trade, participant, final_state)
        if expected <= 0:
            return b11_invoice is None  # nothing will be owed, no invoice needed
        invoice = self._validate_payout_invoice(b11_invoice, expected)
        if invoice is None:
            return False
        participant.payout_invoice = b11_invoice
        return True

    def _handle_collaborative_confirm(self, request: dict, sender_pubkey: str, request_event_id: str,
                                      *, event_created_at: int):
        """
        Once both trade parties called this the trade is finished and the receiver gets
        the payout (trade amount - fee + bond refund).
        """
        try:
            trade_id, trade, participant = self._get_trade_and_participant(request, sender_pubkey)

            if trade.state != TradeState.ONGOING:
                raise ValueError(f"trade not in ongoing state: {trade.state.name}")

            if event_created_at < participant.last_action_ts:
                raise ValueError("stale request, you took another action since")
            participant.last_action_ts = event_created_at
            participant.confirmed = True
            participant.cancel_requested = False
            invoice_accepted = self._store_candidate_payout_invoice(
                trade, participant, request.get('payout_invoice'), TradeState.FINISHED)
            self.wallet.save_db()

            participants = trade.trade_participants
            if participants.maker.confirmed and participants.taker and participants.taker.confirmed:
                self._finalize_trade(trade_id, TradeState.FINISHED)

            response = self._trade_state_response(trade, participant)
            response["payout_invoice_accepted"] = invoice_accepted
            self._respond(content=response, recipient_pubkey=sender_pubkey, request_event_id=request_event_id)
            self.logger.info(f"Participant confirmed trade {trade_id}")

        except ValueError as e:
            self.logger.info(f"Failed to confirm trade: {e!r}")
            self._respond_error(str(e), sender_pubkey, request_event_id)
        except Exception:
            self.logger.exception("Failed to confirm trade")
            self._respond_error("internal error", sender_pubkey, request_event_id)

    def _handle_collaborative_cancel(self, request: dict, sender_pubkey: str, request_event_id: str,
                                     *, event_created_at: int):
        """
        While there is no funded taker the maker can cancel unilaterally. Afterwards both
        parties have to request cancellation. On cancel everyone gets back what they paid.
        """
        try:
            trade_id, trade, participant = self._get_trade_and_participant(request, sender_pubkey)

            if trade.state == TradeState.WAITING_FOR_TAKER:
                if participant is not trade.trade_participants.maker:
                    raise ValueError("only the maker can cancel an untaken trade")
                taker = trade.trade_participants.taker
                if taker and taker.funding_request_key:
                    taker_req = self.wallet.get_request(taker.funding_request_key)
                    if taker_req and self.wallet.get_invoice_status(taker_req) == PR_PAID:
                        # the taker funded concurrently, this is not an untaken trade anymore
                        self._handle_taker_funding(trade_id)
                        raise ValueError("the taker has already funded the trade, "
                                         "cancellation now requires both parties")
                # drop an unfunded taker slot if there is one
                self._clear_taker_slot(trade)
                self._store_candidate_payout_invoice(
                    trade, participant, request.get('payout_invoice'), TradeState.CANCELLED)
                self._finalize_trade(trade_id, TradeState.CANCELLED)
            elif trade.state in (TradeState.ONGOING, TradeState.MEDIATION):
                if event_created_at < participant.last_action_ts:
                    raise ValueError("stale request, you took another action since")
                participant.last_action_ts = event_created_at
                participant.cancel_requested = True
                participant.confirmed = False
                self._store_candidate_payout_invoice(
                    trade, participant, request.get('payout_invoice'), TradeState.CANCELLED)
                self.wallet.save_db()
                participants = trade.trade_participants
                if participants.maker.cancel_requested \
                        and participants.taker and participants.taker.cancel_requested:
                    self._finalize_trade(trade_id, TradeState.CANCELLED)
            else:
                raise ValueError(f"trade cannot be cancelled in state: {trade.state.name}")

            response = self._trade_state_response(trade, participant)
            self._respond(content=response, recipient_pubkey=sender_pubkey, request_event_id=request_event_id)
            self.logger.info(f"Participant requested cancellation of trade {trade_id}")

        except ValueError as e:
            self.logger.info(f"Failed to cancel trade: {e!r}")
            self._respond_error(str(e), sender_pubkey, request_event_id)
        except Exception:
            self.logger.exception("Failed to cancel trade")
            self._respond_error("internal error", sender_pubkey, request_event_id)

    def _handle_request_mediation(self, request: dict, sender_pubkey: str, request_event_id: str):
        """
        Can be called unilaterally, if one party requests this the trade goes in mediation mode.
        Now the traders have to contact the agent out of band (e.g. Signal) and the agent has to
        decide who gets paid how much (see resolve_mediation).
        """
        try:
            trade_id, trade, participant = self._get_trade_and_participant(request, sender_pubkey)

            if trade.state == TradeState.ONGOING:
                trade.state = TradeState.MEDIATION
                self.wallet.save_db()
                trigger_callback('escrow_trades_updated', self.wallet)
                other = trade.trade_participants.maker if participant is not trade.trade_participants.maker \
                    else trade.trade_participants.taker
                self._notify_participant(other, TradeRPC.TRADE_STATE_CHANGED, trade_id)
                self.logger.info(f"Trade {trade_id} went into mediation")
            elif trade.state != TradeState.MEDIATION:  # requesting again is idempotent
                raise ValueError(f"cannot request mediation in state: {trade.state.name}")

            response = self._trade_state_response(trade, participant)
            self._respond(content=response, recipient_pubkey=sender_pubkey, request_event_id=request_event_id)

        except ValueError as e:
            self.logger.info(f"Failed to start mediation: {e!r}")
            self._respond_error(str(e), sender_pubkey, request_event_id)
        except Exception:
            self.logger.exception("Failed to start mediation")
            self._respond_error("internal error", sender_pubkey, request_event_id)

    def _handle_get_trade_state(self, request: dict, sender_pubkey: str, request_event_id: str):
        """Returns the current trade state so participants can sync their local view."""
        try:
            trade_id, trade, participant = self._get_trade_and_participant(request, sender_pubkey)
            response = self._trade_state_response(trade, participant)
            self._respond(content=response, recipient_pubkey=sender_pubkey, request_event_id=request_event_id)
        except ValueError as e:
            self._respond_error(str(e), sender_pubkey, request_event_id)
        except Exception:
            self.logger.exception("Failed to get trade state")
            self._respond_error("internal error", sender_pubkey, request_event_id)

    def _handle_claim_payout(self, request: dict, sender_pubkey: str, request_event_id: str):
        """
        A participant submits a (new) payout invoice for their outstanding allocation.
        Used after mediation, or when the original payout invoice expired or failed.
        """
        try:
            trade_id, trade, participant = self._get_trade_and_participant(request, sender_pubkey)

            if not trade.state.is_final():
                raise ValueError(f"trade not finalized yet: {trade.state.name}")
            due = participant.payout_due_sat or 0
            if due <= 0:
                raise ValueError("no payout due for you in this trade")
            if participant.payout_paid:
                raise ValueError("payout was already paid")

            old_key = participant.payout_invoice_key
            if old_key and old_key in self._payments_in_flight:
                raise ValueError("a payout attempt is in progress right now, wait for it to finish")
            if old_key and old_key in self._lightning_invoices_to_pay:
                old_invoice = self.wallet.get_invoice(old_key)
                if old_invoice and not old_invoice.has_expired():
                    raise ValueError("a payout attempt is already in progress, wait for it to finish")
                # previous invoice is dead, drop it and accept the new one
                self._lightning_invoices_to_pay.pop(old_key, None)

            invoice = self._validate_payout_invoice(request.get('payout_invoice'), due)
            if invoice is None:
                raise ValueError(f"invalid payout invoice, expected amount: {due} sat")

            self._register_payout_invoice(participant, invoice)
            self.wallet.save_db()

            response = self._trade_state_response(trade, participant)
            self._respond(content=response, recipient_pubkey=sender_pubkey, request_event_id=request_event_id)
            self.logger.info(f"Registered payout claim for trade {trade_id}")

        except ValueError as e:
            self.logger.info(f"Failed to claim payout: {e!r}")
            self._respond_error(str(e), sender_pubkey, request_event_id)
        except Exception:
            self.logger.exception("Failed to claim payout")
            self._respond_error("internal error", sender_pubkey, request_event_id)

    def _finalize_trade(self, trade_id: str, final_state: TradeState):
        """
        Sets the final trade state and the payout allocations, and schedules automatic
        payouts for participants that already submitted a valid payout invoice.
        Participants without a usable invoice can claim their allocation later.
        """
        trade = self._trades[trade_id]
        assert final_state.is_final(), final_state
        for participant in trade.trade_participants.both():
            due = self._projected_payout_sat(trade, participant, final_state)
            participant.payout_due_sat = due
            if due <= 0:
                participant.payout_paid = False
                continue
            invoice = self._validate_payout_invoice(participant.payout_invoice, due)
            if invoice is not None:
                self._register_payout_invoice(participant, invoice)
            else:
                self.logger.info(f"no usable payout invoice for trade {trade_id}, "
                                 f"participant can claim {due} sat")
        trade.state = final_state
        self.wallet.save_db()
        trigger_callback('escrow_trades_updated', self.wallet)
        for participant in trade.trade_participants.both():
            self._notify_participant(participant, TradeRPC.TRADE_STATE_CHANGED, trade_id)
        self.logger.info(f"finalized trade {trade_id} as {final_state.name}")

    def resolve_mediation(self, trade_id: str, *, maker_payout_sat: int, taker_payout_sat: int):
        """
        Called by the agent (GUI) after deciding a mediation outcome.
        The participants are notified and can claim their allocations.
        """
        trade = self._trades[trade_id]
        if trade.state != TradeState.MEDIATION:
            raise ValueError("trade is not in mediation")
        participants = trade.trade_participants
        assert participants.taker is not None
        if maker_payout_sat < 0 or taker_payout_sat < 0:
            raise ValueError("payouts cannot be negative")
        if maker_payout_sat + taker_payout_sat > trade.contract.pot_sat():
            raise ValueError("payouts exceed the trade pot")
        for participant, due in ((participants.maker, maker_payout_sat),
                                 (participants.taker, taker_payout_sat)):
            participant.payout_due_sat = due
            if due > 0:
                # invoices submitted earlier were for different amounts, participants claim instead
                invoice = self._validate_payout_invoice(participant.payout_invoice, due)
                if invoice is not None:
                    self._register_payout_invoice(participant, invoice)
        trade.state = TradeState.FINISHED
        self.wallet.save_db()
        trigger_callback('escrow_trades_updated', self.wallet)
        for participant in participants.both():
            self._notify_participant(participant, TradeRPC.TRADE_STATE_CHANGED, trade_id)
        self.logger.info(f"resolved mediation of trade {trade_id}: "
                         f"maker {maker_payout_sat} sat, taker {taker_payout_sat} sat")

    # ---------- payouts ----------

    def _register_payout_invoice(self, participant: TradeParticipant, invoice: Invoice):
        """
        Registers a validated invoice to be paid. The payment loop will pick it up.
        Callers must validate the invoice amount against the participant allocation before.
        """
        self.wallet.save_invoice(invoice)
        key = invoice.get_id()
        participant.payout_invoice_key = key
        self._lightning_invoices_to_pay[key] = int(time.time())

    def _mark_payout_paid(self, invoice_key: str):
        for trade_id, trade in self._trades.items():
            for participant in trade.trade_participants.both():
                if participant.payout_invoice_key == invoice_key:
                    participant.payout_paid = True
                    self.wallet.save_db()
                    trigger_callback('escrow_trades_updated', self.wallet)
                    self._notify_participant(participant, TradeRPC.TRADE_STATE_CHANGED, trade_id)
                    self.logger.info(f"payout for trade {trade_id} paid")
                    return

    async def _pay_pending_lightning_invoices(self):
        while True:
            await asyncio.sleep(10)
            now = int(time.time())
            for key, not_before in list(self._lightning_invoices_to_pay.items()):
                if key in self._payments_in_flight:
                    continue
                if now < not_before:
                    continue

                invoice = self.wallet.get_invoice(key)
                if invoice is None:
                    self.logger.warning("payout invoice missing from wallet, dropping it")
                    self._lightning_invoices_to_pay.pop(key, None)
                    continue

                if invoice.has_expired():
                    # not deleting the invoice from the wallet so the user can see what was going on
                    self.logger.warning("dropping expired payout invoice, recipient can claim again")
                    self._lightning_invoices_to_pay.pop(key, None)
                    continue

                if now - invoice.time > PAYOUT_TIMEOUT_SEC:
                    self.logger.warning(f"could not pay invoice within {PAYOUT_TIMEOUT_SEC=}, giving up")
                    self._lightning_invoices_to_pay.pop(key, None)
                    continue

                self._payments_in_flight.add(key)
                try:
                    await self._pay_invoice(invoice)
                finally:
                    self._payments_in_flight.discard(key)

    async def _pay_invoice(self, invoice: Invoice):
        key = invoice.get_id()
        self.logger.info('trying to pay payout invoice')
        try:
            success, log = await self.wallet.lnworker.pay_invoice(invoice)
        except Exception as e:
            self.logger.info(f'exception paying invoice {key}, retrying in {PAYOUT_INTERVAL_SEC}s: {e!r}')
            self._lightning_invoices_to_pay[key] = int(time.time()) + PAYOUT_INTERVAL_SEC
            return
        if not success:
            self.logger.info(f'failed to pay {key}, will retry in {PAYOUT_INTERVAL_SEC}s')
            self._lightning_invoices_to_pay[key] = int(time.time()) + PAYOUT_INTERVAL_SEC
        else:
            self.logger.info(f'paid invoice {key}')
            self._lightning_invoices_to_pay.pop(key, None)
            self._mark_payout_paid(key)

    # ---------- agent presence broadcasting ----------

    def broadcast_profile_event(self, profile_data: EscrowAgentProfile):
        content = {
            "name": profile_data.name,
            "about": profile_data.about,
            "languages": profile_data.languages,
            "service_fee_ppm": profile_data.service_fee_ppm,
        }
        if profile_data.gpg_fingerprint:
            content["gpg_fingerprint"] = profile_data.gpg_fingerprint
        if profile_data.picture:
            content["picture"] = profile_data.picture
        if profile_data.website:
            content["website"] = profile_data.website
        tags = [
            get_protocol_tag(),
            get_net_tag(),
        ]
        self.nostr_worker.broadcast_agent_profile_event(
            content=content,
            tags=tags,
            signing_key=self.nostr_identity_private_key,
        )

    async def _maybe_rebroadcast_profile_event(self):
        """
        Rebroadcast the profile on startup and every PROFILE_EVENT_INTERVAL_SEC to ensure
        it is always widely available on relays.
        """
        while True:
            profile = self.get_profile()
            if profile:
                self.broadcast_profile_event(profile)
            await asyncio.sleep(PROFILE_EVENT_INTERVAL_SEC)

    async def _broadcast_relay_event(self):
        """
        Broadcast our list of relays from time to time to ensure clients know which
        relays the agent is active on.
        """
        previous_relays = None
        last_broadcast = 0
        while True:
            relays = self.wallet.config.get_nostr_relays()
            if relays:
                # broadcast if our relays have changed or if timeout
                if relays != previous_relays or (int(time.time()) - last_broadcast) > RELAY_EVENT_INTERVAL_SEC:
                    previous_relays, last_broadcast = relays, int(time.time())
                    self.nostr_worker.broadcast_agent_relay_event(
                        relays=relays,
                        signing_key=self.nostr_identity_private_key,
                    )
            await asyncio.sleep(120)

    async def _broadcast_status_event(self):
        """
        Publishes a status event every STATUS_EVENT_INTERVAL_SEC so clients can see the
        agent is available and useful dynamic information of the agent (like liquidity).
        """
        await asyncio.sleep(30)  # wait for channel reestablish on startup, otherwise we announce 0 liquidity
        tags = [
            get_protocol_tag(),
            get_net_tag(),
        ]
        while True:
            content = {
                'inbound_liquidity_sat': self._keep_leading_digits(int(self.wallet.lnworker.num_sats_can_receive() or 0), 2),
                'outbound_liquidity_sat': self._keep_leading_digits(int(self.wallet.lnworker.num_sats_can_send() or 0), 2),
            }
            self.nostr_worker.broadcast_agent_status_event(
                content=content,
                tags=tags,
                signing_key=self.nostr_identity_private_key,
            )
            await asyncio.sleep(STATUS_EVENT_INTERVAL_SEC)

    @staticmethod
    def _keep_leading_digits(num: int, digits: int) -> int:
        """Reduces precision of num to `digits` leading digits."""
        if num <= 0:
            return 0
        num_str = str(num)
        zeroed_num_str = f"{num_str[:digits]}{(len(num_str[digits:])) * '0'}"
        return int(zeroed_num_str)

    def get_profile(self) -> Optional[EscrowAgentProfile]:
        if 'profile' not in self.storage:
            return None
        try:
            return EscrowAgentProfile.from_remote_dict(dict(self.storage['profile']))
        except ValueError:
            self.logger.warning("stored agent profile is invalid")
            return None

    def save_profile(self, profile_data: EscrowAgentProfile) -> None:
        self.storage['profile'] = dataclasses.asdict(profile_data)
        self.wallet.save_db()
        self.broadcast_profile_event(profile_data)
