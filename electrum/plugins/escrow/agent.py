import time
import json
import dataclasses
from typing import TYPE_CHECKING, Optional
import asyncio

from electrum_aionostr.event import Event as nEvent

from electrum.util import OldTaskGroup, InvoiceError
from electrum import constants
from electrum.invoices import Invoice

from .escrow_worker import EscrowWorker, EscrowAgentProfile

if TYPE_CHECKING:
    from .nostr_worker import EscrowNostrWorker
    from electrum.wallet import Abstract_Wallet


class EscrowAgent(EscrowWorker):
    STATUS_EVENT_INTERVAL_SEC = 1800  # 30 min
    PROFILE_EVENT_INTERVAL_SEC = 1_209_600  # 2 weeks
    RELAY_EVENT_INTERVAL_SEC = 1_209_800  # 2 weeks
    # ~3m, time after which we give up to pay a customer and just keep their money, they can contact out of band
    PAYOUT_TIMEOUT_SEC = 7_776_000
    PAYOUT_INTERVAL_SEC = 1800  # how often we try to pay out an invoice

    def __init__(self, wallet: 'Abstract_Wallet', nostr_worker: 'EscrowNostrWorker', storage: dict):
        EscrowWorker.__init__(self, wallet, nostr_worker, storage)
        assert wallet.has_lightning(), "Wallet needs lightning support"

        # wallet key -> next payment attempt ts
        if 'pending_lightning_invoices' not in storage:
            storage['pending_lightning_invoices'] = {}
        self._lightning_invoices_to_pay = storage['pending_lightning_invoices']  # type: dict[str, int]

        # we derive a persistent nostr identity from the wallet
        self.nostr_identity_private_key = nostr_worker.get_nostr_privkey_for_wallet(wallet)

    async def main_loop(self):
        self.logger.debug(f"escrow agent started: {self.wallet.basename()}")
        tasks = (
            self._broadcast_status_event(),
            self._maybe_rebroadcast_profile_event(),
            self._broadcast_relay_event(),
            self._handle_requests(),
            self._pay_pending_lightning_invoices(),
        )
        async with OldTaskGroup() as g:
            for task in tasks:
                await g.spawn(task)
                await asyncio.sleep(3)  # prevent getting rate limited by relays

    async def _handle_requests(self):
        query = {
            "kinds": [self.nostr_worker.EPHEMERAL_REQUEST_EVENT_KIND],
            "#p": [self.nostr_identity_private_key.public_key.hex()],
            "#r": [f"net:{constants.net.NET_NAME}"],
            "#d": [f"electrum-escrow-plugin-{self.NOSTR_PROTOCOL_VERSION}"],
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
                try:
                    content = privkey.decrypt_message(event.content, event.pubkey)
                    content = json.loads(content)
                    if not isinstance(content, dict):
                        raise Exception("malformed content, not dict")
                except Exception:
                    continue

                # todo: some priority queue prioritizing existing trade rpcs over new trade rpcs would be nice
                method = content.get('method')
                match method:
                    case 'register_escrow':
                        self._handle_register_escrow(content)
                    case 'collaborative_confirm':
                        self._handle_collaborative_confirm(content)
                    case 'collaborative_cancel':
                        self._handle_collaborative_cancel(content)
                    case 'handle_mediation':
                        self._handle_request_mediation(content)
                    case _:
                        continue

    def _handle_register_escrow(self, request: dict):
        """
        Each trade participant should call this once.
        First call is the maker, second call is the taker.
        """
        pass

    def _handle_collaborative_confirm(self, request: dict):
        """
        Once both trade parties called this the trade is marked done. Bond and amount have
        to get paid back to the trade participants.
        """
        pass

    def _handle_collaborative_cancel(self, request: dict):
        """
        If only one participant is registered yet the trade gets canceled.
        If both are registered already both have to request collaborative cancel to cancel the trade.
        """
        pass

    def _handle_request_mediation(self, request: dict):
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

                if int(time.time()) - invoice.time > self.PAYOUT_TIMEOUT_SEC:
                    self.logger.warn(f"we didn't manage to pay invoice in {self.PAYOUT_TIMEOUT_SEC=}, giving up")
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
            self.logger.info(f'failed to pay {invoice.get_id()}, will retry in {self.PAYOUT_INTERVAL_SEC=}')
            self._lightning_invoices_to_pay[invoice.get_id()] = int(time.time()) + self.PAYOUT_INTERVAL_SEC
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
            ['d', f'electrum-escrow-plugin-{str(self.NOSTR_PROTOCOL_VERSION)}'],
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
            await asyncio.sleep(self.PROFILE_EVENT_INTERVAL_SEC)

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
                if relays != previous_relays or (int(time.time()) - last_broadcast) > self.RELAY_EVENT_INTERVAL_SEC:
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
            ['d', f'electrum-escrow-plugin-{str(self.NOSTR_PROTOCOL_VERSION)}'],
            ['r', 'net:' + constants.net.NET_NAME],
        ]
        while True:
            content = {
                'inbound_liquidity_sat': self._keep_leading_digits(self.wallet.lnworker.num_sats_can_receive() or 0, 2),
                'outbound_liquidity_sat': self._keep_leading_digits(self.wallet.lnworker.num_sats_can_receive() or 0, 2),
            }
            self.nostr_worker.broadcast_agent_status_event(
                content=content,
                tags=tags,
                signing_key=self.nostr_identity_private_key,
            )
            await asyncio.sleep(self.STATUS_EVENT_INTERVAL_SEC)

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
