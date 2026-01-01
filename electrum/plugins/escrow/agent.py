import time
import json
import secrets
import dataclasses
from typing import TYPE_CHECKING, Optional
import asyncio

from electrum_aionostr.event import Event as nEvent

from electrum.util import OldTaskGroup, InvoiceError, EventListener, event_listener
from electrum import constants
from electrum.invoices import Invoice, PR_PAID
from electrum.bitcoin import is_address

from .escrow_worker import (
    EscrowWorker, EscrowAgentProfile, TradeContract
)
from .constants import (
    STATUS_EVENT_INTERVAL_SEC, PROFILE_EVENT_INTERVAL_SEC, RELAY_EVENT_INTERVAL_SEC,
    DIRECT_MESSAGE_EXPIRATION_SEC, PAYOUT_TIMEOUT_SEC, PAYOUT_INTERVAL_SEC,
    MAX_AMOUNT_PENDING_TRADES, SUPPORTED_PAYMENT_PROTOCOLS, PROTOCOL_VERSION,
    TradeState, TradePaymentProtocol, TradeRPC, TradePaymentDirection,
    MAX_TITLE_LEN_CHARS, MAX_CONTRACT_LEN_CHARS, MIN_TRADE_AMOUNT_SAT,
    EPHEMERAL_REQUEST_EVENT_KIND,
)

if TYPE_CHECKING:
    from .nostr_worker import EscrowNostrWorker
    from electrum.wallet import Abstract_Wallet


@dataclasses.dataclass
class TradeParticipant:
    pubkey: str
    funding_request_key: str
    onchain_fallback_address: str  # so we can refund/payout onchain in case lightning fails
    contract_signature: str  # signature over 'ESCROW'|title|contract|trade_amount|bond_amount

    def to_json(self):
        return dataclasses.asdict(self)

@dataclasses.dataclass
class TradeParticipants:
    maker: TradeParticipant
    taker: Optional[TradeParticipant] = None

    def to_json(self):
        return dataclasses.asdict(self)

@dataclasses.dataclass
class AgentEscrowTrade:
    state: TradeState
    trade_participants: TradeParticipants
    contract: TradeContract
    payment_protocol: TradePaymentProtocol
    trade_protocol_version: int
    creation_timestamp: int = dataclasses.field(default_factory=lambda: int(time.time()))

    def to_json(self):
        return dataclasses.asdict(self)


class EscrowAgent(EscrowWorker, EventListener):
    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict):
        EscrowWorker.__init__(self, wallet, nostr_worker, storage)
        assert wallet.has_lightning(), "Wallet needs lightning support"

        # wallet key -> next payment attempt ts
        if 'pending_lightning_invoices' not in storage:
            storage['pending_lightning_invoices'] = {}
        self._lightning_invoices_to_pay = storage['pending_lightning_invoices']  # type: dict[str, int]

        # we derive a persistent nostr identity from the wallet
        self.nostr_identity_private_key = nostr_worker.get_nostr_privkey_for_wallet(wallet)

        if 'trades' not in storage:
            storage['trades'] = {}
        self._trades = storage['trades']  # type: dict[str, AgentEscrowTrade]

        # newly registered trades, waiting for the maker to send us the funds. We only persist the
        # trade once the invoice is paid to avoid writing every request to the db, or when shutting down.
        self._pending_trades = {}  # type: dict[str, AgentEscrowTrade]

        self.register_callbacks()

    async def main_loop(self):
        self.logger.debug(f"escrow agent started: {self.wallet.basename()}")
        tasks = (
            self._broadcast_status_event(),
            self._maybe_rebroadcast_profile_event(),
            self._broadcast_relay_event(),
            self._handle_requests(),
            self._pay_pending_lightning_invoices(),
            self._cleanup_pending_trades_funding_expired(),
        )
        async with OldTaskGroup() as g:
            for task in tasks:
                await g.spawn(task)
                await asyncio.sleep(3)  # prevent getting rate limited by relays

    def stop(self):
        self._cleanup_pending_trades()
        self.unregister_callbacks()
        EscrowWorker.stop(self)

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
            if trade.trade_participants.taker.funding_request_key == key:
                self._handle_taker_funding(trade_id)
                return

    def _handle_maker_funding(self, trade_id: str):
        """Maker has paid their funding invoice. Now the trade can get persisted in the db."""
        assert trade_id not in self._trades, trade_id
        self._trades[trade_id] = self._pending_trades.pop(trade_id)
        self.logger.info(f"maker funding received: {trade_id=}")

    def _handle_taker_funding(self, trade_id: str):
        """Taker has paid their funding invoice. Maker must already have paid before."""
        trade = self._trades[trade_id]
        assert trade.state < TradeState.ONGOING, trade.state
        trade.state = TradeState.ONGOING
        self.logger.info(f"taker funding received: {trade_id=}")
        self._notify_maker_trade_funded(trade_id)

    def _notify_maker_trade_funded(self, trade_id: str):
        """
        Notifies the maker that the taker has funded the trade contract.
        The maker then knows that the trade state is "ONGOING" and the exchange of goods can begin.
        """
        trade = self._trades[trade_id]
        maker_pubkey = trade.trade_participants.maker.pubkey
        msg = {
            "method": TradeRPC.TRADE_FUNDED.value,
            "trade_id": trade_id,
        }
        # the event can't be ephemeral as the maker might not be online to receive it. so we set an
        # expiration of DIRECT_MESSAGE_EXPIRATION_SEC which should be longer than any sane trade duration
        self.nostr_worker.send_encrypted_direct_message(
            cleartext_content=msg,
            recipient_pubkey=maker_pubkey,
            expiration_duration=DIRECT_MESSAGE_EXPIRATION_SEC,
            signing_key=self.nostr_identity_private_key,
        )

    def _add_new_trade(self, trade: AgentEscrowTrade) -> str:
        """
        Evicts oldest unfunded trade if MAX_AMOUNT_PENDING_TRADES is exceeded.
        Returns new trade id.
        """
        if len(self._pending_trades) >= MAX_AMOUNT_PENDING_TRADES:
            oldest_key = min(self._pending_trades, key=lambda k: self._pending_trades[k].creation_timestamp)
            funding_request_key = self._pending_trades[oldest_key].trade_participants.maker.funding_request_key
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
            self.wallet.delete_request(funding_request_key)
        self._pending_trades.clear()

    async def _cleanup_pending_trades_funding_expired(self):
        """
        Delete pending trades for which the funding invoice has expired before the maker paid it.
        Maker invoices are supposed to be very short-lived, so this should keep the dict tidy and clean.
        """
        while True:
            await asyncio.sleep(30)
            for trade_id, trade in list(self._pending_trades.items()):
                funding_req_key = trade.trade_participants.maker.funding_request_key
                req = self.wallet.get_request(funding_req_key)
                if req.has_expired():
                    self.wallet.delete_request(funding_req_key)
                    del self._pending_trades[trade_id]

    async def _handle_requests(self):
        query = {
            "kinds": [EPHEMERAL_REQUEST_EVENT_KIND],
            "#p": [self.nostr_identity_private_key.public_key.hex()],
            "#r": [f"net:{constants.net.NET_NAME}"],
            "#d": [f"electrum-escrow-plugin-{PROTOCOL_VERSION}"],
            "limit": 0,
        }
        privkey = self.nostr_identity_private_key
        event_queue = asyncio.Queue(maxsize=1000)
        while True:
            _job_id = self.nostr_worker.fetch_events(query, event_queue)
            while True:
                await asyncio.sleep(0.1)
                event = await event_queue.get()
                if event is None:
                    await asyncio.sleep(10)  # query job got canceled, maybe proxy changed
                    break
                assert isinstance(event, nEvent)
                pubkey = event.pubkey
                try:
                    content = privkey.decrypt_message(event.content, pubkey)
                    content = json.loads(content)
                    if not isinstance(content, dict):
                        raise Exception("malformed content, not dict")
                except Exception:
                    continue

                # todo: some priority queue prioritizing existing trade rpcs over new trade rpcs would be nice
                try:
                    method = TradeRPC(content.get('method'))
                except ValueError:
                    continue

                match method:
                    case TradeRPC.REGISTER_ESCROW:
                        self._handle_register_escrow(content, pubkey, event.id)
                    case TradeRPC.ACCEPT_ESCROW:
                        self._handle_accept_escrow(content, pubkey, event.id)
                    case TradeRPC.COLLABORATIVE_CONFIRM:
                        self._handle_collaborative_confirm(content, pubkey, event.id)
                    case TradeRPC.COLLABORATIVE_CANCEL:
                        self._handle_collaborative_cancel(content, pubkey, event.id)
                    case TradeRPC.REQUEST_MEDIATION:
                        self._handle_request_mediation(content, pubkey, event.id)
                    case _:
                        raise NotImplementedError()

    def _handle_register_escrow(self, request: dict, sender_pubkey: str, request_event_id: str):
        """
        The maker trade should call this to register a new escrow contract.
        """
        try:
            title = request.get("title")
            if not title or len(title) > MAX_TITLE_LEN_CHARS:
                raise ValueError("invalid title")

            contract = request.get("contract")
            if not contract or len(contract) > MAX_CONTRACT_LEN_CHARS:
                raise ValueError("invalid contract")

            onchain_fallback_address = request.get("onchain_fallback_address")
            if not onchain_fallback_address or not is_address(onchain_fallback_address):
                raise ValueError("invalid onchain fallback address")

            payment_protocol = TradePaymentProtocol(request.get("payment_protocol"))
            if payment_protocol not in SUPPORTED_PAYMENT_PROTOCOLS:
                raise ValueError("unsupported payment_protocol")

            payment_network = request.get("payment_network")
            if payment_network != constants.net.NET_NAME:
                raise ValueError("invalid payment_network")

            trade_protocol = request.get("trade_protocol_version")
            if trade_protocol != PROTOCOL_VERSION:
                raise ValueError(f"invalid trade_protocol_version: {trade_protocol} != {PROTOCOL_VERSION}")

            trade_amount_sat = request.get("trade_amount_sat")
            if not trade_amount_sat or trade_amount_sat < MIN_TRADE_AMOUNT_SAT:
                raise ValueError(f"no or too small trade_amount_sat: {MIN_TRADE_AMOUNT_SAT=}")

            bond_amount_sat = request.get("bond_amount_sat")
            if bond_amount_sat is None:
                raise ValueError("bond_amount_sat is missing")

            contract = TradeContract(
                title=title,
                contract=contract,
                trade_amount_sat=trade_amount_sat,
                bond_sat=bond_amount_sat,
            )

            signature = request.get('contract_signature')
            if not signature or not contract.verify(sig_hex=signature, pubkey_hex=sender_pubkey):
                raise ValueError("invalid contract_signature")

            payment_direction = TradePaymentDirection(request.get('payment_direction'))

            # Create funding invoice
            message = f"Escrow funding: {contract.title}"
            amount_sat = trade_amount_sat if payment_direction == TradePaymentDirection.SENDING else bond_amount_sat
            req_key = self.wallet.create_request(
                amount_sat=amount_sat,
                message=message,
                exp_delay=600,  # 10 min, the maker should pay right away in the wizard
                address=None
            )
            req = self.wallet.get_request(req_key)
            bolt11 = self.wallet.get_bolt11_invoice(req)

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
                payment_protocol=payment_protocol,
                trade_protocol_version=trade_protocol,
            )

            trade_id = self._add_new_trade(trade)

            response = {
                "trade_id": trade_id,
                "bolt11_invoice": bolt11,
            }

            self.nostr_worker.send_encrypted_ephemeral_message(
                cleartext_content=response,
                recipient_pubkey=sender_pubkey,
                signing_key=self.nostr_identity_private_key,
                response_to_id=request_event_id,
            )
            self.logger.info(f"Registered new trade {trade_id} for {sender_pubkey}")
        except Exception as e:
            self.logger.error(f"Failed to register escrow: {repr(e)}")
            self.nostr_worker.send_encrypted_ephemeral_message(
                cleartext_content={"error": str(e)},
                recipient_pubkey=sender_pubkey,
                signing_key=self.nostr_identity_private_key,
                response_to_id=request_event_id,
            )

    def _handle_accept_escrow(self, request: dict, sender_pubkey: str, request_event_id: str):
        """
        Sent by taker to accept an escrow contract the maker has previously registered.
        """
        pass

    def _handle_collaborative_confirm(self, request: dict, sender_pubkey: str, request_event_id: str):
        """
        Once both trade parties called this the trade is marked done. Bond and amount have
        to get paid back to the trade participants.
        """
        pass

    def _handle_collaborative_cancel(self, request: dict, sender_pubkey: str, request_event_id: str):
        """
        If only one participant is registered yet the trade gets canceled.
        If both are registered already both have to request collaborative cancel to cancel the trade.
        """
        pass

    def _handle_request_mediation(self, request: dict, sender_pubkey: str, request_event_id: str):
        """
        Can be called unilaterally, if one party requests this the trade goes in mediation mode.
        Now the traders have to contact the agent out of band (e.g. Signal) and the agent has to decide
        who gets paid how much.
        """
        pass

    def _register_payout_invoice(self, *, b11_invoice: str, expected_amount_sat: int):
        """
        Register an invoice to be paid. Will immediately try to get this invoice paid.
        WARNING: Validate before that we haven't already paid the user requesting payout.
        """
        try:
            invoice = Invoice.from_bech32(b11_invoice)
        except InvoiceError:
            self.logger.warn(f"got invalid invoice, rejecting")
            return
        if not invoice.get_amount_sat() == expected_amount_sat:
            raise ValueError(f"invalid invoice amount: {invoice.get_amount_sat()}")
        self.wallet.save_invoice(invoice)
        key = invoice.get_id()
        self._lightning_invoices_to_pay[key] = int(time.time())

    async def _pay_pending_lightning_invoices(self):
        while True:
            await asyncio.sleep(10)
            for key, not_before in list(self._lightning_invoices_to_pay.items()):
                if int(time.time()) < not_before:
                    continue

                invoice = self.wallet.get_invoice(key)

                if invoice.has_expired():
                    self.logger.warn(f"dropping expired lightning invoice")
                    # not deleting the invoice from the wallet so the user can see what was going on
                    del self._lightning_invoices_to_pay[key]
                    continue

                if int(time.time()) - invoice.time > PAYOUT_TIMEOUT_SEC:
                    self.logger.warn(f"we didn't manage to pay invoice in {PAYOUT_TIMEOUT_SEC=}, giving up")
                    del self._lightning_invoices_to_pay[key]
                    continue

                self._lightning_invoices_to_pay[key] += 1000000000000 # lock
                await self._pay_invoice(invoice)

    async def _pay_invoice(self, invoice: Invoice):
        self.logger.info(f'trying to pay invoice')
        try:
            success, log = await self.wallet.lnworker.pay_invoice(invoice)
        except Exception:
            self.logger.exception(f'exception paying invoice {invoice.get_id()}, will not retry')
            del self._lightning_invoices_to_pay[invoice.get_id()]
            return
        if not success:
            self.logger.info(f'failed to pay {invoice.get_id()}, will retry in {PAYOUT_INTERVAL_SEC=}')
            self._lightning_invoices_to_pay[invoice.get_id()] = int(time.time()) + PAYOUT_INTERVAL_SEC
        else:
            self.logger.info(f'paid invoice {invoice.get_id()}')
            del self._lightning_invoices_to_pay[invoice.get_id()]

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
            ['d', f'electrum-escrow-plugin-{str(PROTOCOL_VERSION)}'],
            ['r', 'net:' + constants.net.NET_NAME],
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
            profile_data = self.storage.get('profile')
            if profile_data:
                profile = EscrowAgentProfile(**profile_data)
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
        Publishes a NIP-38 status event every STATUS_EVENT_INTERVAL_SEC so clients can see the
        agent is available and useful dynamic information of the agent (like liquidity).
        """
        await asyncio.sleep(30)  # wait for channel reestablish on startup, otherwise we announce 0 liquidity
        tags = [
            ['d', f'electrum-escrow-plugin-{str(PROTOCOL_VERSION)}'],
            ['r', 'net:' + constants.net.NET_NAME],
        ]
        while True:
            content = {
                'inbound_liquidity_sat': self._keep_leading_digits(self.wallet.lnworker.num_sats_can_receive() or 0, 2),
                'outbound_liquidity_sat': self._keep_leading_digits(self.wallet.lnworker.num_sats_can_send() or 0, 2),
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
        return EscrowAgentProfile(**self.storage['profile'])

    def save_profile(self, profile_data: EscrowAgentProfile) -> None:
        self.storage['profile'] = dataclasses.asdict(profile_data)
        self.broadcast_profile_event(profile_data)
