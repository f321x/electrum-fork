import json
import os
import time
from decimal import Decimal
from types import SimpleNamespace
from typing import Optional

from electrum import constants
from electrum.bip32 import BIP32Node
from electrum.bitcoin import COIN, pubkey_to_address
from electrum.bolt11 import BOLT11Addr, encode_bolt11_invoice
from electrum.invoices import Invoice, PR_PAID, PR_UNPAID
from electrum.json_db import JsonDB
from electrum.lnutil import LnFeatures, generate_keypair
from electrum.util import MyEncoder, UserFacingException
from electrum_ecc import ECPrivkey
from electrum_aionostr.key import PrivateKey
from electrum_aionostr.event import Event as nEvent

from electrum.plugins.escrow.agent import (
    EscrowAgent, AgentEscrowTrade, TradeParticipant, TradeParticipants,
)
from electrum.plugins.escrow.backup import NostrStateBackup
from electrum.plugins.escrow.client import EscrowClient, ClientEscrowTrade
from electrum.plugins.escrow.escrow_worker import (
    TradeContract, EscrowAgentProfile, EscrowWorker, NOSTR_KEY_FAMILY_ESCROW,
)
from electrum.plugins.escrow import constants as escrow_constants
from electrum.plugins.escrow.constants import (
    TradeState, TradePaymentDirection, TradePaymentProtocol, TradeRPC, PROTOCOL_VERSION,
)

from .. import ElectrumTestCase


BOLT11_PRIVKEY = bytes.fromhex('e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734')
FEE_PPM = 10_000  # 1%


def make_bolt11(amount_sat: Optional[int], expiry: int = 3600, date: int = None) -> str:
    addr = BOLT11Addr(
        paymenthash=os.urandom(32),
        amount=Decimal(amount_sat) / COIN if amount_sat else None,
        tags=[
            ('d', 'test'),
            ('x', expiry),
            ('9', LnFeatures.VAR_ONION_OPT | LnFeatures.PAYMENT_SECRET_REQ),
        ],
        payment_secret=os.urandom(32),
        date=date,
    )
    return encode_bolt11_invoice(addr, BOLT11_PRIVKEY)


def make_address() -> str:
    privkey = ECPrivkey(os.urandom(32))
    return pubkey_to_address('p2wpkh', privkey.get_public_key_bytes().hex())


class MockRequest:
    def __init__(self, amount_sat: int, bolt11: str):
        self.amount_sat = amount_sat
        self.bolt11 = bolt11
        self.expired = False
        self.paid = False

    def has_expired(self) -> bool:
        return self.expired


class MockLNWorker:
    def __init__(self):
        self.can_send = 10**8
        self.can_receive = 10**8
        self.paid_invoices = []
        self.pay_success = True

    def num_sats_can_send(self):
        return self.can_send

    def num_sats_can_receive(self):
        return self.can_receive

    async def pay_invoice(self, invoice):
        self.paid_invoices.append(invoice)
        return self.pay_success, []


class MockWallet:
    def __init__(self):
        self.lnworker = MockLNWorker()
        self.network = SimpleNamespace()  # a closed wallet has network = None
        # each mock wallet gets its own lightning master key, like a real wallet
        self.db = {'lightning_xprv': BIP32Node.from_rootseed(os.urandom(32), xtype='standard').to_xprv()}
        self.config = SimpleNamespace(get_nostr_relays=lambda: [])
        self.requests = {}
        self.invoices = {}
        self._req_counter = 0
        self.save_db_calls = 0

    def has_lightning(self) -> bool:
        return self.lnworker is not None

    def basename(self) -> str:
        return 'mock_wallet'

    def save_db(self):
        self.save_db_calls += 1

    def create_request(self, amount_sat, message, exp_delay, address):
        key = f'req{self._req_counter}'
        self._req_counter += 1
        self.requests[key] = MockRequest(amount_sat, make_bolt11(amount_sat or None))
        return key

    def get_request(self, key):
        return self.requests.get(key)

    def delete_request(self, key, **kwargs):
        self.requests.pop(key, None)

    def get_bolt11_invoice(self, req) -> str:
        return req.bolt11

    def get_invoice_status(self, req):
        return PR_PAID if getattr(req, 'paid', False) else PR_UNPAID

    def save_invoice(self, invoice, **kwargs):
        self.invoices[invoice.get_id()] = invoice

    def get_invoice(self, key):
        return self.invoices.get(key)

    def delete_invoice(self, key, **kwargs):
        self.invoices.pop(key, None)

    def get_unused_address(self):
        return make_address()

    def get_receiving_address(self):
        return make_address()


class MockNostrWorker:
    def __init__(self):
        self.ephemeral_messages = []  # (content, recipient_pubkey, response_to_id)
        self.dms = []  # (content, recipient_pubkey)
        self.broadcasts = []
        self.replaceable_events = []  # kwargs of broadcast_replaceable_event
        self.stored_events = []  # events served to fetch_events queries
        self.fetch_queries = []
        self.fetch_jobs_die = True  # whether fetch jobs end after serving stored_events

    def send_encrypted_ephemeral_message(self, *, cleartext_content, recipient_pubkey,
                                         signing_key, response_to_id=None):
        self.ephemeral_messages.append((cleartext_content, recipient_pubkey, response_to_id))

    def send_encrypted_direct_message(self, *, cleartext_content, recipient_pubkey,
                                      expiration_duration, signing_key) -> str:
        self.dms.append((cleartext_content, recipient_pubkey))
        return 'dm_event_id'

    def broadcast_agent_profile_event(self, **kwargs):
        self.broadcasts.append(kwargs)

    def broadcast_replaceable_event(self, **kwargs):
        self.replaceable_events.append(kwargs)

    def fetch_events(self, query, output_queue):
        self.fetch_queries.append(query)
        for event in self.stored_events:
            output_queue.put_nowait(event)
        if self.fetch_jobs_die:
            output_queue.put_nowait(None)
        return 'job_id'

    def cancel_job(self, job_id):
        pass

    def last_response(self) -> dict:
        return self.ephemeral_messages[-1][0]


def make_contract(agent_pubkey: str, *, amount=100_000, bond=3_000, fee=FEE_PPM,
                  direction=TradePaymentDirection.SENDING) -> TradeContract:
    return TradeContract(
        title='Test Trade',
        text='The seller ships a widget within 7 days.',
        trade_amount_sat=amount,
        bond_sat=bond,
        agent_fee_ppm=fee,
        maker_payment_direction=direction,
        payment_protocol=TradePaymentProtocol.BITCOIN_LIGHTNING,
        agent_pubkey=agent_pubkey,
    )


def wire_roundtrip(obj) -> dict:
    """Simulates serializing an object over the wire."""
    return json.loads(json.dumps(obj, cls=MyEncoder))


class TestTradeContract(ElectrumTestCase):

    def test_hash_changes_with_fields(self):
        base_hash = make_contract('ab' * 32).contract_hash()
        self.assertEqual(base_hash, make_contract('ab' * 32).contract_hash())
        variations = [
            make_contract('ab' * 32, amount=99_999),
            make_contract('ab' * 32, bond=1),
            make_contract('ab' * 32, fee=1),
            make_contract('ab' * 32, direction=TradePaymentDirection.RECEIVING),
            make_contract('cd' * 32),
        ]
        for contract in variations:
            self.assertNotEqual(base_hash, contract.contract_hash())

    def test_sign_verify(self):
        contract = make_contract('ab' * 32)
        key = PrivateKey()
        sig = contract.sign(privkey_hex=key.hex())
        self.assertTrue(contract.verify(sig_hex=sig, pubkey_hex=key.public_key.hex()))
        # wrong key fails
        self.assertFalse(contract.verify(sig_hex=sig, pubkey_hex=PrivateKey().public_key.hex()))
        # tampered contract fails
        tampered = make_contract('ab' * 32, amount=100_001)
        self.assertFalse(tampered.verify(sig_hex=sig, pubkey_hex=key.public_key.hex()))
        # malformed inputs return False instead of raising
        self.assertFalse(contract.verify(sig_hex='zz', pubkey_hex='not hex'))

    def test_from_remote_dict_validation(self):
        contract = make_contract('ab' * 32)
        good = wire_roundtrip(contract.to_json())
        restored = TradeContract.from_remote_dict(dict(good))
        self.assertEqual(restored.contract_hash(), contract.contract_hash())

        with self.assertRaises(ValueError):
            TradeContract.from_remote_dict(None)
        with self.assertRaises(ValueError):  # missing field
            d = dict(good); d.pop('title')
            TradeContract.from_remote_dict(d)
        with self.assertRaises(ValueError):  # unexpected extra field
            TradeContract.from_remote_dict({**good, 'extra': 1})
        with self.assertRaises(ValueError):  # negative bond
            TradeContract.from_remote_dict({**good, 'bond_sat': -1})
        with self.assertRaises(ValueError):  # amount too small
            TradeContract.from_remote_dict({**good, 'trade_amount_sat': 1})
        with self.assertRaises(ValueError):  # bool masquerading as int
            TradeContract.from_remote_dict({**good, 'trade_amount_sat': True})
        with self.assertRaises(ValueError):  # amount as string
            TradeContract.from_remote_dict({**good, 'trade_amount_sat': '10000'})
        with self.assertRaises(ValueError):  # fee out of range
            TradeContract.from_remote_dict({**good, 'agent_fee_ppm': 2_000_000})
        with self.assertRaises(ValueError):  # bad agent pubkey
            TradeContract.from_remote_dict({**good, 'agent_pubkey': 'xyz'})
        with self.assertRaises(ValueError):  # bad direction
            TradeContract.from_remote_dict({**good, 'maker_payment_direction': 7})

    def test_amount_helpers(self):
        contract = make_contract('ab' * 32, amount=100_000, bond=3_000, fee=10_000)
        self.assertEqual(contract.agent_fee_sat(), 1_000)
        self.assertEqual(contract.payout_amount_sat(), 100_000 - 1_000 + 3_000)
        self.assertEqual(contract.pot_sat(), 103_000)
        self.assertEqual(contract.funding_amount_sat(TradePaymentDirection.SENDING), 100_000)
        self.assertEqual(contract.funding_amount_sat(TradePaymentDirection.RECEIVING), 3_000)
        self.assertEqual(contract.payment_direction(is_maker=True), TradePaymentDirection.SENDING)
        self.assertEqual(contract.payment_direction(is_maker=False), TradePaymentDirection.RECEIVING)


class TestAgentProfile(ElectrumTestCase):

    def test_from_remote_dict(self):
        good = {
            'name': 'Agent', 'about': 'I mediate.', 'languages': ['en', 'de'],
            'service_fee_ppm': 5000,
        }
        profile = EscrowAgentProfile.from_remote_dict(good)
        self.assertEqual(profile.name, 'Agent')
        self.assertIsNone(profile.picture)

        with self.assertRaises(ValueError):
            EscrowAgentProfile.from_remote_dict({**good, 'service_fee_ppm': 'free'})
        with self.assertRaises(ValueError):
            EscrowAgentProfile.from_remote_dict({**good, 'service_fee_ppm': -1})
        with self.assertRaises(ValueError):
            EscrowAgentProfile.from_remote_dict({**good, 'name': ''})
        with self.assertRaises(ValueError):
            EscrowAgentProfile.from_remote_dict({**good, 'languages': 'en'})
        with self.assertRaises(ValueError):
            EscrowAgentProfile.from_remote_dict({**good, 'picture': 123})
        # regular nostr profiles with extra fields are fine
        profile = EscrowAgentProfile.from_remote_dict({**good, 'lud16': 'a@b.com'})
        self.assertEqual(profile.service_fee_ppm, 5000)


class AgentTestCase(ElectrumTestCase):
    """Base with helpers to drive an EscrowAgent through trade flows."""

    def make_agent(self, wallet: MockWallet = None, storage: dict = None) -> EscrowAgent:
        wallet = wallet or MockWallet()
        nostr = MockNostrWorker()
        agent = EscrowAgent(wallet, nostr, storage if storage is not None else {})
        self.addCleanup(agent.stop)
        profile = EscrowAgentProfile(
            name='Agent', about='I mediate.', languages=['en'], service_fee_ppm=FEE_PPM)
        agent.storage['profile'] = {
            'name': profile.name, 'about': profile.about, 'languages': profile.languages,
            'service_fee_ppm': profile.service_fee_ppm, 'gpg_fingerprint': None,
            'picture': None, 'website': None,
        }
        return agent

    def register_trade(self, agent: EscrowAgent, contract: TradeContract = None,
                       maker_key: PrivateKey = None, **contract_kwargs) -> tuple[PrivateKey, dict]:
        maker_key = maker_key or PrivateKey()
        if contract is None:
            contract = make_contract(agent.get_identity_pubkey(), **contract_kwargs)
        request = {
            'method': TradeRPC.REGISTER_ESCROW.value,
            'contract': wire_roundtrip(contract.to_json()),
            'contract_signature': contract.sign(privkey_hex=maker_key.hex()),
            'onchain_fallback_address': make_address(),
            'payment_network': constants.net.NET_NAME,
            'trade_protocol_version': PROTOCOL_VERSION,
        }
        agent._handle_register_escrow(request, maker_key.public_key.hex(), 'reg_event')
        return maker_key, agent.nostr_worker.last_response()

    def fund_maker(self, agent: EscrowAgent, trade_id: str):
        trade = agent._pending_trades[trade_id]
        req_key = trade.trade_participants.maker.funding_request_key
        agent.wallet.requests[req_key].paid = True
        agent.on_event_request_status(agent.wallet, req_key, PR_PAID)

    def accept_trade(self, agent: EscrowAgent, trade_id: str,
                     taker_key: PrivateKey = None) -> tuple[PrivateKey, dict]:
        taker_key = taker_key or PrivateKey()
        trade = agent._trades[trade_id]
        request = {
            'method': TradeRPC.ACCEPT_ESCROW.value,
            'trade_id': trade_id,
            'contract_signature': trade.contract.sign(privkey_hex=taker_key.hex()),
            'onchain_fallback_address': make_address(),
        }
        agent._handle_accept_escrow(request, taker_key.public_key.hex(), 'acc_event')
        return taker_key, agent.nostr_worker.last_response()

    def fund_taker(self, agent: EscrowAgent, trade_id: str):
        trade = agent._trades[trade_id]
        req_key = trade.trade_participants.taker.funding_request_key
        agent.wallet.requests[req_key].paid = True
        agent.on_event_request_status(agent.wallet, req_key, PR_PAID)

    def make_funded_trade(self, agent: EscrowAgent, **contract_kwargs) \
            -> tuple[str, PrivateKey, PrivateKey]:
        """Registers, accepts and funds a trade. Returns (trade_id, maker_key, taker_key)."""
        maker_key, response = self.register_trade(agent, **contract_kwargs)
        trade_id = response['trade_id']
        self.fund_maker(agent, trade_id)
        taker_key, _resp = self.accept_trade(agent, trade_id)
        self.fund_taker(agent, trade_id)
        self.assertEqual(agent._trades[trade_id].state, TradeState.ONGOING)
        return trade_id, maker_key, taker_key

    _event_ts_counter = 0

    def _next_event_ts(self) -> int:
        AgentTestCase._event_ts_counter += 1
        return int(time.time()) + AgentTestCase._event_ts_counter

    def confirm(self, agent: EscrowAgent, trade_id: str, key: PrivateKey,
                payout_invoice: Optional[str] = None, event_ts: int = None) -> dict:
        request = {
            'method': TradeRPC.COLLABORATIVE_CONFIRM.value,
            'trade_id': trade_id,
            'payout_invoice': payout_invoice,
        }
        agent._handle_collaborative_confirm(
            request, key.public_key.hex(), 'conf_event',
            event_created_at=event_ts if event_ts is not None else self._next_event_ts())
        return agent.nostr_worker.last_response()

    def cancel(self, agent: EscrowAgent, trade_id: str, key: PrivateKey,
               payout_invoice: Optional[str] = None, event_ts: int = None) -> dict:
        request = {
            'method': TradeRPC.COLLABORATIVE_CANCEL.value,
            'trade_id': trade_id,
            'payout_invoice': payout_invoice,
        }
        agent._handle_collaborative_cancel(
            request, key.public_key.hex(), 'canc_event',
            event_created_at=event_ts if event_ts is not None else self._next_event_ts())
        return agent.nostr_worker.last_response()


class TestAgentRegistration(AgentTestCase):

    async def test_register_and_fund(self):
        agent = self.make_agent()
        maker_key, response = self.register_trade(agent)
        self.assertNotIn('error', response)
        trade_id = response['trade_id']
        self.assertIn(trade_id, agent._pending_trades)
        self.assertNotIn(trade_id, agent._trades)
        # maker is SENDING by default, so the funding invoice is over the trade amount
        invoice = Invoice.from_bech32(response['bolt11_invoice'])
        self.assertEqual(invoice.get_amount_sat(), 100_000)

        self.fund_maker(agent, trade_id)
        self.assertIn(trade_id, agent._trades)
        self.assertNotIn(trade_id, agent._pending_trades)
        self.assertEqual(agent._trades[trade_id].state, TradeState.WAITING_FOR_TAKER)

    async def test_register_receiving_maker_pays_bond(self):
        agent = self.make_agent()
        _maker_key, response = self.register_trade(
            agent, direction=TradePaymentDirection.RECEIVING)
        invoice = Invoice.from_bech32(response['bolt11_invoice'])
        self.assertEqual(invoice.get_amount_sat(), 3_000)

    async def test_register_zero_funding_skips_invoice(self):
        agent = self.make_agent()
        # maker receives and there is no bond: nothing to pay, trade is live right away
        _maker_key, response = self.register_trade(
            agent, direction=TradePaymentDirection.RECEIVING, bond=0)
        self.assertNotIn('error', response)
        self.assertIsNone(response['bolt11_invoice'])
        self.assertIn(response['trade_id'], agent._trades)

    async def test_register_rejections(self):
        agent = self.make_agent()
        maker_key = PrivateKey()

        def register(contract, *, sig_key=None, mutate=None):
            sig_key = sig_key or maker_key
            request = {
                'method': TradeRPC.REGISTER_ESCROW.value,
                'contract': wire_roundtrip(contract.to_json()),
                'contract_signature': contract.sign(privkey_hex=sig_key.hex()),
                'onchain_fallback_address': make_address(),
                'payment_network': constants.net.NET_NAME,
                'trade_protocol_version': PROTOCOL_VERSION,
            }
            if mutate:
                mutate(request)
            agent._handle_register_escrow(request, maker_key.public_key.hex(), 'evt')
            return agent.nostr_worker.last_response()

        # wrong agent pubkey in contract
        response = register(make_contract('ee' * 32))
        self.assertIn('different agent', response['error'])
        # fee mismatch
        response = register(make_contract(agent.get_identity_pubkey(), fee=FEE_PPM + 1))
        self.assertIn('fee mismatch', response['error'])
        # signature by some other key
        response = register(make_contract(agent.get_identity_pubkey()), sig_key=PrivateKey())
        self.assertIn('signature', response['error'])
        # tampered amount after signing
        def bump_amount(request):
            request['contract']['trade_amount_sat'] += 1
        response = register(make_contract(agent.get_identity_pubkey()), mutate=bump_amount)
        self.assertIn('signature', response['error'])
        # wrong network
        def wrong_net(request):
            request['payment_network'] = 'lalaland'
        response = register(make_contract(agent.get_identity_pubkey()), mutate=wrong_net)
        self.assertIn('payment_network', response['error'])
        # bad fallback address
        def bad_addr(request):
            request['onchain_fallback_address'] = 'nonsense'
        response = register(make_contract(agent.get_identity_pubkey()), mutate=bad_addr)
        self.assertIn('address', response['error'])
        # not enough inbound liquidity
        agent.wallet.lnworker.can_receive = 10
        response = register(make_contract(agent.get_identity_pubkey()))
        self.assertIn('liquidity', response['error'])
        agent.wallet.lnworker.can_receive = 10**8
        # no profile configured
        del agent.storage['profile']
        response = register(make_contract(agent.get_identity_pubkey()))
        self.assertIn('not configured', response['error'])

        self.assertEqual(len(agent._pending_trades), 0)

    async def test_unfunded_maker_trade_expires(self):
        agent = self.make_agent()
        _maker_key, response = self.register_trade(agent)
        trade_id = response['trade_id']
        trade = agent._pending_trades[trade_id]
        req_key = trade.trade_participants.maker.funding_request_key
        agent.wallet.requests[req_key].expired = True
        # simulate one round of the cleanup task
        for pending_id, pending in list(agent._pending_trades.items()):
            key = pending.trade_participants.maker.funding_request_key
            if agent._is_funding_request_expired(key):
                agent.wallet.delete_request(key)
                agent._pending_trades.pop(pending_id, None)
        self.assertNotIn(trade_id, agent._pending_trades)
        self.assertNotIn(req_key, agent.wallet.requests)


class TestAgentAccept(AgentTestCase):

    async def test_accept_flow(self):
        agent = self.make_agent()
        _maker_key, response = self.register_trade(agent)
        trade_id = response['trade_id']
        self.fund_maker(agent, trade_id)

        _taker_key, response = self.accept_trade(agent, trade_id)
        self.assertNotIn('error', response)
        # taker is the receiver here, so they pay the bond
        invoice = Invoice.from_bech32(response['bolt11_invoice'])
        self.assertEqual(invoice.get_amount_sat(), 3_000)
        self.assertEqual(agent._trades[trade_id].state, TradeState.WAITING_FOR_TAKER)

        self.fund_taker(agent, trade_id)
        self.assertEqual(agent._trades[trade_id].state, TradeState.ONGOING)
        # the maker got notified that the trade is funded
        dm_content, dm_recipient = agent.nostr_worker.dms[-1]
        self.assertEqual(dm_content['method'], TradeRPC.TRADE_FUNDED.value)
        self.assertEqual(dm_recipient, agent._trades[trade_id].trade_participants.maker.pubkey)

    async def test_maker_cannot_take_own_trade(self):
        agent = self.make_agent()
        maker_key, response = self.register_trade(agent)
        trade_id = response['trade_id']
        self.fund_maker(agent, trade_id)
        _taker_key, response = self.accept_trade(agent, trade_id, taker_key=maker_key)
        self.assertIn('own trade', response['error'])

    async def test_taker_slot_is_protected_and_recoverable(self):
        agent = self.make_agent()
        _maker_key, response = self.register_trade(agent)
        trade_id = response['trade_id']
        self.fund_maker(agent, trade_id)

        taker1, response = self.accept_trade(agent, trade_id)
        self.assertNotIn('error', response)
        # second taker is rejected while the first funding invoice is alive
        _taker2, response = self.accept_trade(agent, trade_id)
        self.assertIn('already registered', response['error'])

        # after the first taker's invoice expires, the slot is freed
        trade = agent._trades[trade_id]
        agent.wallet.requests[trade.trade_participants.taker.funding_request_key].expired = True
        taker3, response = self.accept_trade(agent, trade_id)
        self.assertNotIn('error', response)
        self.assertEqual(trade.trade_participants.taker.pubkey, taker3.public_key.hex())

    async def test_unknown_trade_and_bad_state(self):
        agent = self.make_agent()
        taker_key = PrivateKey()
        request = {
            'method': TradeRPC.ACCEPT_ESCROW.value,
            'trade_id': 'ff' * 32,
            'contract_signature': 'a' * 128,
            'onchain_fallback_address': make_address(),
        }
        agent._handle_accept_escrow(request, taker_key.public_key.hex(), 'evt')
        self.assertIn('not found', agent.nostr_worker.last_response()['error'])


class TestAgentResolution(AgentTestCase):

    async def test_collaborative_confirm_pays_receiver(self):
        agent = self.make_agent()
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        trade = agent._trades[trade_id]
        payout_amount = trade.contract.payout_amount_sat()

        # the maker (sender) confirms first
        response = self.confirm(agent, trade_id, maker_key)
        self.assertNotIn('error', response)
        self.assertTrue(response['maker_confirmed'])
        self.assertFalse(response['taker_confirmed'])
        self.assertEqual(TradeState(response['state']), TradeState.ONGOING)

        # the taker (receiver) confirms with their payout invoice
        payout_invoice = make_bolt11(payout_amount)
        response = self.confirm(agent, trade_id, taker_key, payout_invoice)
        self.assertNotIn('error', response)
        self.assertTrue(response['payout_invoice_accepted'])
        self.assertEqual(TradeState(response['state']), TradeState.FINISHED)
        self.assertEqual(response['payout_due_sat'], payout_amount)

        taker = trade.trade_participants.taker
        self.assertEqual(taker.payout_due_sat, payout_amount)
        self.assertEqual(trade.trade_participants.maker.payout_due_sat, 0)
        # payout is registered for payment
        self.assertIn(taker.payout_invoice_key, agent._lightning_invoices_to_pay)
        # both parties were notified
        notified = {dm[1] for dm in agent.nostr_worker.dms}
        self.assertIn(maker_key.public_key.hex(), notified)
        self.assertIn(taker_key.public_key.hex(), notified)

    async def test_confirm_with_bad_invoice_is_claimable(self):
        agent = self.make_agent()
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        trade = agent._trades[trade_id]
        payout_amount = trade.contract.payout_amount_sat()

        self.confirm(agent, trade_id, maker_key)
        # receiver submits an invoice over a wrong amount
        response = self.confirm(agent, trade_id, taker_key, make_bolt11(payout_amount - 1))
        self.assertFalse(response['payout_invoice_accepted'])
        self.assertEqual(TradeState(response['state']), TradeState.FINISHED)
        taker = trade.trade_participants.taker
        self.assertEqual(taker.payout_due_sat, payout_amount)
        self.assertIsNone(taker.payout_invoice_key)  # nothing registered

        # now the taker claims with a correct invoice
        request = {
            'method': TradeRPC.CLAIM_PAYOUT.value,
            'trade_id': trade_id,
            'payout_invoice': make_bolt11(payout_amount),
        }
        agent._handle_claim_payout(request, taker_key.public_key.hex(), 'claim_event')
        response = agent.nostr_worker.last_response()
        self.assertNotIn('error', response)
        self.assertIn(taker.payout_invoice_key, agent._lightning_invoices_to_pay)

        # claiming again while the payout is pending is rejected
        agent._handle_claim_payout(request, taker_key.public_key.hex(), 'claim_event2')
        self.assertIn('in progress', agent.nostr_worker.last_response()['error'])

    async def test_sender_cannot_claim(self):
        agent = self.make_agent()
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        self.confirm(agent, trade_id, maker_key)
        self.confirm(agent, trade_id, taker_key,
                     make_bolt11(agent._trades[trade_id].contract.payout_amount_sat()))
        request = {
            'method': TradeRPC.CLAIM_PAYOUT.value,
            'trade_id': trade_id,
            'payout_invoice': make_bolt11(1000),
        }
        agent._handle_claim_payout(request, maker_key.public_key.hex(), 'claim_event')
        self.assertIn('no payout due', agent.nostr_worker.last_response()['error'])

    async def test_non_participant_is_rejected(self):
        agent = self.make_agent()
        trade_id, _maker_key, _taker_key = self.make_funded_trade(agent)
        stranger = PrivateKey()
        response = self.confirm(agent, trade_id, stranger)
        self.assertIn('not a participant', response['error'])
        request = {'method': TradeRPC.GET_TRADE_STATE.value, 'trade_id': trade_id}
        agent._handle_get_trade_state(request, stranger.public_key.hex(), 'evt')
        self.assertIn('not a participant', agent.nostr_worker.last_response()['error'])

    async def test_maker_unilateral_cancel_before_taker(self):
        agent = self.make_agent()
        maker_key, response = self.register_trade(agent)
        trade_id = response['trade_id']
        self.fund_maker(agent, trade_id)
        trade = agent._trades[trade_id]

        refund_invoice = make_bolt11(100_000)  # maker paid the trade amount
        response = self.cancel(agent, trade_id, maker_key, refund_invoice)
        self.assertNotIn('error', response)
        self.assertEqual(TradeState(response['state']), TradeState.CANCELLED)
        maker = trade.trade_participants.maker
        self.assertEqual(maker.payout_due_sat, 100_000)
        self.assertIn(maker.payout_invoice_key, agent._lightning_invoices_to_pay)

    async def test_taker_cannot_cancel_unilaterally(self):
        agent = self.make_agent()
        trade_id, _maker_key, taker_key = self.make_funded_trade(agent)
        response = self.cancel(agent, trade_id, taker_key)
        self.assertNotIn('error', response)
        # trade is still ongoing, only one side requested cancellation
        self.assertEqual(TradeState(response['state']), TradeState.ONGOING)
        self.assertTrue(response['taker_cancel_requested'])

    async def test_bilateral_cancel_refunds_both(self):
        agent = self.make_agent()
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        trade = agent._trades[trade_id]

        self.cancel(agent, trade_id, taker_key, make_bolt11(3_000))  # taker paid the bond
        response = self.cancel(agent, trade_id, maker_key, make_bolt11(100_000))
        self.assertEqual(TradeState(response['state']), TradeState.CANCELLED)
        self.assertEqual(trade.trade_participants.maker.payout_due_sat, 100_000)
        self.assertEqual(trade.trade_participants.taker.payout_due_sat, 3_000)
        self.assertEqual(len(agent._lightning_invoices_to_pay), 2)

    async def test_confirm_and_cancel_votes_switch(self):
        agent = self.make_agent()
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        trade = agent._trades[trade_id]
        maker = trade.trade_participants.maker

        self.confirm(agent, trade_id, maker_key)
        self.assertTrue(maker.confirmed)
        self.cancel(agent, trade_id, maker_key, make_bolt11(100_000))
        self.assertFalse(maker.confirmed)
        self.assertTrue(maker.cancel_requested)
        # switching back to confirm clears the cancel vote
        self.confirm(agent, trade_id, maker_key)
        self.assertTrue(maker.confirmed)
        self.assertFalse(maker.cancel_requested)
        self.assertEqual(trade.state, TradeState.ONGOING)

    async def test_cancel_in_final_state_rejected(self):
        agent = self.make_agent()
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        self.confirm(agent, trade_id, maker_key)
        self.confirm(agent, trade_id, taker_key)
        response = self.cancel(agent, trade_id, maker_key)
        self.assertIn('cannot be cancelled', response['error'])

    async def test_replayed_old_vote_cannot_flip_newer_vote(self):
        # a malicious relay replays an old confirm event after the participant cancelled
        agent = self.make_agent()
        trade_id, maker_key, _taker_key = self.make_funded_trade(agent)
        maker = agent._trades[trade_id].trade_participants.maker

        confirm_ts = self._next_event_ts()
        self.confirm(agent, trade_id, maker_key, event_ts=confirm_ts)
        self.cancel(agent, trade_id, maker_key, make_bolt11(100_000),
                    event_ts=confirm_ts + 10)
        self.assertTrue(maker.cancel_requested)

        # replaying the older confirm event must not flip the vote back
        response = self.confirm(agent, trade_id, maker_key, event_ts=confirm_ts)
        self.assertIn('stale', response['error'])
        self.assertTrue(maker.cancel_requested)
        self.assertFalse(maker.confirmed)

    async def test_cancel_race_with_taker_funding(self):
        # the maker tries to unilaterally cancel while the taker's funding payment
        # already settled but the payment event was not processed yet
        agent = self.make_agent()
        _maker_key, response = self.register_trade(agent)
        trade_id = response['trade_id']
        maker_key = _maker_key
        self.fund_maker(agent, trade_id)
        _taker_key, _resp = self.accept_trade(agent, trade_id)
        trade = agent._trades[trade_id]
        # taker pays, but on_event_request_status was not called yet
        agent.wallet.requests[trade.trade_participants.taker.funding_request_key].paid = True

        response = self.cancel(agent, trade_id, maker_key, make_bolt11(100_000))
        self.assertIn('already funded', response['error'])
        # the trade transitioned to ongoing instead of being cancelled
        self.assertEqual(trade.state, TradeState.ONGOING)
        self.assertIsNotNone(trade.trade_participants.taker)


class TestAgentMediation(AgentTestCase):

    def request_mediation(self, agent, trade_id, key) -> dict:
        request = {'method': TradeRPC.REQUEST_MEDIATION.value, 'trade_id': trade_id}
        agent._handle_request_mediation(request, key.public_key.hex(), 'med_event')
        return agent.nostr_worker.last_response()

    async def test_mediation_flow(self):
        agent = self.make_agent()
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        trade = agent._trades[trade_id]

        response = self.request_mediation(agent, trade_id, maker_key)
        self.assertEqual(TradeState(response['state']), TradeState.MEDIATION)
        # the other side got notified
        dm_content, dm_recipient = agent.nostr_worker.dms[-1]
        self.assertEqual(dm_content['method'], TradeRPC.TRADE_STATE_CHANGED.value)
        self.assertEqual(dm_recipient, taker_key.public_key.hex())

        # requesting again is idempotent
        response = self.request_mediation(agent, trade_id, taker_key)
        self.assertNotIn('error', response)

        # confirms are not possible during mediation
        response = self.confirm(agent, trade_id, maker_key)
        self.assertIn('error', response)

        # agent decides: maker gets 40k, taker gets 60k, agent keeps the rest of the pot
        agent.resolve_mediation(trade_id, maker_payout_sat=40_000, taker_payout_sat=60_000)
        self.assertEqual(trade.state, TradeState.FINISHED)
        self.assertEqual(trade.trade_participants.maker.payout_due_sat, 40_000)
        self.assertEqual(trade.trade_participants.taker.payout_due_sat, 60_000)

        # participants claim their allocations
        for key, amount in ((maker_key, 40_000), (taker_key, 60_000)):
            request = {
                'method': TradeRPC.CLAIM_PAYOUT.value,
                'trade_id': trade_id,
                'payout_invoice': make_bolt11(amount),
            }
            agent._handle_claim_payout(request, key.public_key.hex(), 'evt')
            self.assertNotIn('error', agent.nostr_worker.last_response())
        self.assertEqual(len(agent._lightning_invoices_to_pay), 2)

    async def test_resolve_validation(self):
        agent = self.make_agent()
        trade_id, maker_key, _taker_key = self.make_funded_trade(agent)
        with self.assertRaises(ValueError):  # not in mediation
            agent.resolve_mediation(trade_id, maker_payout_sat=1, taker_payout_sat=1)
        self.request_mediation(agent, trade_id, maker_key)
        pot = agent._trades[trade_id].contract.pot_sat()
        with self.assertRaises(ValueError):  # exceeds pot
            agent.resolve_mediation(trade_id, maker_payout_sat=pot, taker_payout_sat=1)
        with self.assertRaises(ValueError):  # negative
            agent.resolve_mediation(trade_id, maker_payout_sat=-1, taker_payout_sat=0)

    async def test_mediation_requires_ongoing_trade(self):
        agent = self.make_agent()
        maker_key, response = self.register_trade(agent)
        trade_id = response['trade_id']
        self.fund_maker(agent, trade_id)
        response = self.request_mediation(agent, trade_id, maker_key)
        self.assertIn('error', response)


class TestAgentPayouts(AgentTestCase):

    async def test_payout_loop_pays_and_marks_paid(self):
        agent = self.make_agent()
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        trade = agent._trades[trade_id]
        payout_amount = trade.contract.payout_amount_sat()
        self.confirm(agent, trade_id, maker_key)
        self.confirm(agent, trade_id, taker_key, make_bolt11(payout_amount))

        taker = trade.trade_participants.taker
        key = taker.payout_invoice_key
        invoice = agent.wallet.get_invoice(key)
        self.assertIsNotNone(invoice)

        await agent._pay_invoice(invoice)
        self.assertTrue(taker.payout_paid)
        self.assertNotIn(key, agent._lightning_invoices_to_pay)
        # the recipient got a state change notification
        dm_content, dm_recipient = agent.nostr_worker.dms[-1]
        self.assertEqual(dm_recipient, taker_key.public_key.hex())

    async def test_failed_payout_is_retried_later(self):
        agent = self.make_agent()
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        trade = agent._trades[trade_id]
        payout_amount = trade.contract.payout_amount_sat()
        self.confirm(agent, trade_id, maker_key)
        self.confirm(agent, trade_id, taker_key, make_bolt11(payout_amount))

        agent.wallet.lnworker.pay_success = False
        taker = trade.trade_participants.taker
        invoice = agent.wallet.get_invoice(taker.payout_invoice_key)
        await agent._pay_invoice(invoice)
        self.assertFalse(taker.payout_paid)
        # still queued, with a retry time in the future
        retry_ts = agent._lightning_invoices_to_pay[taker.payout_invoice_key]
        self.assertGreater(retry_ts, int(time.time()))


class TestClientPostbox(ElectrumTestCase):

    def make_client(self) -> EscrowClient:
        wallet = MockWallet()
        nostr = MockNostrWorker()
        client = EscrowClient(wallet, nostr, storage={})
        self.addCleanup(client.stop)
        return client

    async def test_postbox_roundtrip(self):
        client = self.make_client()
        agent_key = PrivateKey()
        contract = make_contract(agent_key.public_key.hex())
        trade_key = client.get_new_privkey_for_trade()
        trade = ClientEscrowTrade(
            state=TradeState.WAITING_FOR_TAKER,
            contract=contract,
            is_maker=True,
            onchain_fallback_address=make_address(),
            private_key_hex=trade_key.hex(),
        )
        client._trades['ab' * 32] = trade

        postbox_key = client.create_trade_postbox('ab' * 32)
        self.assertTrue(postbox_key.startswith('trade1'))
        self.assertEqual(trade.postbox_key, postbox_key)

        # the dm is addressed to the postbox pubkey and decryptable with the postbox key
        dm_content, dm_recipient = client.nostr_worker.dms[-1]
        from electrum.segwit_addr import bech32_decode, convertbits
        decoded = bech32_decode(bech=postbox_key, ignore_long_length=True)
        postbox_privkey = PrivateKey(bytes(convertbits(decoded.data, 5, 8, pad=False)))
        self.assertEqual(dm_recipient, postbox_privkey.public_key.hex())

        # taker parses the postbox content
        taker_client = self.make_client()
        content = wire_roundtrip(dm_content)
        parsed_trade, parsed_id = taker_client._parse_postbox_content(
            content, maker_pubkey=trade_key.public_key.hex())
        self.assertEqual(parsed_id, 'ab' * 32)
        self.assertEqual(parsed_trade.contract.contract_hash(), contract.contract_hash())
        self.assertFalse(parsed_trade.is_maker)
        self.assertEqual(parsed_trade.payment_direction, TradePaymentDirection.RECEIVING)

        # tampering with the contract invalidates the maker signature
        tampered = wire_roundtrip(dm_content)
        tampered['contract']['trade_amount_sat'] += 1
        with self.assertRaises(ValueError):
            taker_client._parse_postbox_content(tampered, maker_pubkey=trade_key.public_key.hex())

        # a postbox signed by a different key is rejected
        with self.assertRaises(ValueError):
            taker_client._parse_postbox_content(content, maker_pubkey=PrivateKey().public_key.hex())

        # wrong network is rejected
        wrong_net = wire_roundtrip(dm_content)
        wrong_net['payment_network'] = 'lalaland'
        with self.assertRaises(ValueError):
            taker_client._parse_postbox_content(wrong_net, maker_pubkey=trade_key.public_key.hex())

    async def test_trade_keys_are_unique(self):
        client = self.make_client()
        keys = {client.get_new_privkey_for_trade().hex() for _ in range(5)}
        self.assertEqual(len(keys), 5)


class TestNostrKeyDerivation(ElectrumTestCase):

    async def test_derived_like_lightning_keys(self):
        wallet = MockWallet()
        identity = EscrowWorker.get_nostr_privkey_for_wallet(wallet)
        # the identity key is the lightning key derivation applied to the escrow key family
        node = BIP32Node.from_xkey(wallet.db['lightning_xprv'])
        self.assertEqual(generate_keypair(node, NOSTR_KEY_FAMILY_ESCROW).privkey.hex(), identity.hex())
        # deterministic, and per-trade keys are distinct from the identity and from each other
        self.assertEqual(identity.hex(), EscrowWorker.get_nostr_privkey_for_wallet(wallet).hex())
        key0 = EscrowWorker.get_nostr_privkey_for_wallet(wallet, key_id=0)
        key1 = EscrowWorker.get_nostr_privkey_for_wallet(wallet, key_id=1)
        self.assertEqual(3, len({identity.hex(), key0.hex(), key1.hex()}))
        # a different wallet derives different keys
        self.assertNotEqual(identity.hex(), EscrowWorker.get_nostr_privkey_for_wallet(MockWallet()).hex())


class TestNostrBackup(AgentTestCase):

    def make_backup_worker(self, wallet: MockWallet, storage: dict) -> NostrStateBackup:
        worker = NostrStateBackup(wallet, MockNostrWorker(), storage)
        self.addCleanup(worker.stop)
        return worker

    def make_restore_target(self, wallet: MockWallet, event_kwargs_list) -> tuple[NostrStateBackup, dict]:
        """A backup worker for a fresh wallet restored from the same seed, with the
        given published backups available on its relays."""
        wallet2 = MockWallet()
        wallet2.db['lightning_xprv'] = wallet.db['lightning_xprv']
        storage2 = {}
        worker = self.make_backup_worker(wallet2, storage2)
        worker.nostr_worker.stored_events.extend(self.as_event(kw) for kw in event_kwargs_list)
        return worker, storage2

    @staticmethod
    def as_event(broadcast_kwargs: dict) -> nEvent:
        return nEvent(
            pubkey=broadcast_kwargs['signing_key'].public_key.hex(),
            kind=broadcast_kwargs['kind'],
            content=broadcast_kwargs['content'],
            tags=[['d', broadcast_kwargs['d_tag']]],
        )

    async def test_client_backup_restore_roundtrip(self):
        wallet = MockWallet()
        storage = {'client_data': {}}
        client = EscrowClient(wallet, MockNostrWorker(), storage['client_data'])
        self.addCleanup(client.stop)
        trade_key = client.get_new_privkey_for_trade()
        agent_key = PrivateKey()
        trade = ClientEscrowTrade(
            state=TradeState.ONGOING,
            contract=make_contract(agent_key.public_key.hex()),
            is_maker=True,
            onchain_fallback_address=make_address(),
            private_key_hex=trade_key.hex(),
            payout_due_sat=123,
        )
        client._trades['ab' * 32] = trade
        client.add_escrow_agent(agent_key.public_key.hex())

        backup = self.make_backup_worker(wallet, storage)
        backup._maybe_publish_backup()
        self.assertEqual(1, len(backup.nostr_worker.replaceable_events))

        restorer, storage2 = self.make_restore_target(
            wallet, backup.nostr_worker.replaceable_events)
        restored_calls = []
        restorer._on_state_restored = lambda: restored_calls.append(1)
        num_trades = await restorer.restore_from_nostr()
        self.assertEqual(1, num_trades)
        self.assertEqual([1], restored_calls)
        self.assertGreater(restorer.wallet.save_db_calls, 0)

        restored = storage2['client_data']['escrow_client_trades']['ab' * 32]
        self.assertIsInstance(restored, ClientEscrowTrade)
        self.assertEqual(restored.contract.contract_hash(), trade.contract.contract_hash())
        self.assertEqual(restored.state, TradeState.ONGOING)
        self.assertEqual(restored.private_key.hex(), trade_key.hex())
        self.assertEqual(restored.payout_due_sat, 123)
        # key counter and agent list survive, so future trade keys are never reused
        self.assertEqual(
            storage2['client_data']['trade_key_counter'],
            storage['client_data']['trade_key_counter'])
        self.assertEqual(storage2['client_data']['agents'], [agent_key.public_key.hex()])
        self.assertFalse(storage2.get('is_escrow_agent'))

    async def test_agent_backup_excludes_payout_queue(self):
        wallet = MockWallet()
        storage = {'is_escrow_agent': True, 'agent_data': {}}
        agent = self.make_agent(wallet=wallet, storage=storage['agent_data'])
        trade_id, maker_key, taker_key = self.make_funded_trade(agent)
        payout_amount = agent._trades[trade_id].contract.payout_amount_sat()
        self.confirm(agent, trade_id, maker_key)
        self.confirm(agent, trade_id, taker_key, make_bolt11(payout_amount))
        self.assertTrue(agent._lightning_invoices_to_pay)  # a payout is queued

        backup = self.make_backup_worker(wallet, storage)
        backup._maybe_publish_backup()
        event_kwargs = backup.nostr_worker.replaceable_events[-1]
        payload = backup._decrypt_payload(event_kwargs['content'])
        self.assertNotIn('pending_lightning_invoices', payload['data']['agent_data'])

        restorer, storage2 = self.make_restore_target(wallet, [event_kwargs])
        num_trades = await restorer.restore_from_nostr()
        self.assertEqual(1, num_trades)
        self.assertTrue(storage2['is_escrow_agent'])
        self.assertEqual(storage2['agent_data']['profile']['name'], 'Agent')
        restored = storage2['agent_data']['escrow_agent_trades'][trade_id]
        self.assertIsInstance(restored, AgentEscrowTrade)
        self.assertEqual(restored.state, TradeState.FINISHED)
        self.assertEqual(restored.trade_participants.taker.payout_due_sat, payout_amount)
        # the payout queue is not resurrected: a restored (possibly stale) backup must
        # never pay out automatically, participants claim their allocations again
        self.assertNotIn('pending_lightning_invoices', storage2['agent_data'])

    async def test_invalid_backups_rejected(self):
        # without any usable candidate the fetch keeps resubscribing until the deadline,
        # so shorten it to keep the test fast
        original_timeout = escrow_constants.BACKUP_FETCH_TIMEOUT_SEC
        escrow_constants.BACKUP_FETCH_TIMEOUT_SEC = 0.2
        self.addCleanup(setattr, escrow_constants, 'BACKUP_FETCH_TIMEOUT_SEC', original_timeout)
        wallet = MockWallet()
        storage = {'client_data': {'trade_key_counter': 3}}
        backup = self.make_backup_worker(wallet, storage)
        backup._maybe_publish_backup()
        good_kwargs = backup.nostr_worker.replaceable_events[-1]

        # tampered ciphertext fails authentication
        content = good_kwargs['content']
        tampered_char = 'A' if content[10] != 'A' else 'B'
        tampered = {**good_kwargs, 'content': content[:10] + tampered_char + content[11:]}
        restorer, _storage2 = self.make_restore_target(wallet, [tampered])
        with self.assertRaises(UserFacingException):
            await restorer.restore_from_nostr()

        # a backup republished by a different author is ignored
        foreign = {**good_kwargs, 'signing_key': PrivateKey()}
        restorer, _storage2 = self.make_restore_target(wallet, [foreign])
        with self.assertRaises(UserFacingException):
            await restorer.restore_from_nostr()

        # payloads of a different network or backup version are rejected
        for key, value in (('network', 'lalaland'), ('version', escrow_constants.BACKUP_VERSION + 1)):
            payload = backup._build_payload({'client_data': {'trade_key_counter': 3}})
            payload[key] = value
            mutated = {**good_kwargs, 'content': backup._encrypt_payload(payload)}
            restorer, _storage2 = self.make_restore_target(wallet, [mutated])
            with self.assertRaises(UserFacingException):
                await restorer.restore_from_nostr()

    async def test_newest_backup_wins(self):
        wallet = MockWallet()
        storage = {'client_data': {'trade_key_counter': 1}}
        backup = self.make_backup_worker(wallet, storage)
        backup._maybe_publish_backup()
        storage['client_data']['trade_key_counter'] = 7
        backup._maybe_publish_backup()
        old_kwargs, new_kwargs = backup.nostr_worker.replaceable_events

        for served_order in ([old_kwargs, new_kwargs], [new_kwargs, old_kwargs]):
            restorer, storage2 = self.make_restore_target(wallet, served_order)
            await restorer.restore_from_nostr()
            self.assertEqual(storage2['client_data']['trade_key_counter'], 7)

    async def test_restore_merges_into_existing_state(self):
        # publish a backup with two trades
        wallet = MockWallet()
        storage = {'client_data': {'escrow_client_trades': {}, 'trade_key_counter': 3}}
        agent_pubkey = PrivateKey().public_key.hex()
        for trade_id in ('aa' * 32, 'bb' * 32):
            storage['client_data']['escrow_client_trades'][trade_id] = ClientEscrowTrade(
                state=TradeState.ONGOING,
                contract=make_contract(agent_pubkey),
                is_maker=True,
                onchain_fallback_address=make_address(),
            )
        backup = self.make_backup_worker(wallet, storage)
        backup._maybe_publish_backup()

        # the restoring wallet already has a newer version of one trade and a higher counter
        restorer, storage2 = self.make_restore_target(
            wallet, backup.nostr_worker.replaceable_events)
        local_trade = ClientEscrowTrade(
            state=TradeState.FINISHED,
            contract=make_contract(agent_pubkey),
            is_maker=True,
            onchain_fallback_address=make_address(),
        )
        storage2['client_data'] = {
            'escrow_client_trades': {'aa' * 32: local_trade},
            'trade_key_counter': 7,
        }
        num_new = await restorer.restore_from_nostr()
        # only the missing trade was added, local data won everywhere else
        self.assertEqual(1, num_new)
        trades = storage2['client_data']['escrow_client_trades']
        self.assertIs(trades['aa' * 32], local_trade)
        self.assertEqual(trades['aa' * 32].state, TradeState.FINISHED)
        self.assertIn('bb' * 32, trades)
        self.assertEqual(storage2['client_data']['trade_key_counter'], 7)

    async def test_publish_only_on_meaningful_change(self):
        wallet = MockWallet()
        storage = {}
        backup = self.make_backup_worker(wallet, storage)
        backup._maybe_publish_backup()
        # empty state is never published, so it cannot overwrite a recoverable backup
        self.assertEqual(0, len(backup.nostr_worker.replaceable_events))
        storage['client_data'] = {'trade_key_counter': 1}
        backup._maybe_publish_backup()
        backup._maybe_publish_backup()  # unchanged state is not republished
        self.assertEqual(1, len(backup.nostr_worker.replaceable_events))
        storage['client_data']['trade_key_counter'] = 2
        backup._maybe_publish_backup()
        self.assertEqual(2, len(backup.nostr_worker.replaceable_events))

    async def test_failed_publish_is_retried(self):
        wallet = MockWallet()
        storage = {'client_data': {'trade_key_counter': 1}}
        backup = self.make_backup_worker(wallet, storage)
        backup._maybe_publish_backup()
        events = backup.nostr_worker.replaceable_events
        self.assertEqual(1, len(events))
        # a confirmed broadcast is not republished while the state is unchanged
        events[-1]['on_result'](True)
        backup._maybe_publish_backup()
        self.assertEqual(1, len(events))
        # when no relay accepted the event, the next check cycle retries the same state
        events[-1]['on_result'](False)
        backup._maybe_publish_backup()
        self.assertEqual(2, len(events))

    async def test_startup_restore(self):
        wallet = MockWallet()
        storage = {'client_data': {'trade_key_counter': 5}}
        backup = self.make_backup_worker(wallet, storage)
        backup._maybe_publish_backup()

        restorer, storage2 = self.make_restore_target(
            wallet, backup.nostr_worker.replaceable_events)
        self.assertFalse(restorer._publish_allowed)
        await restorer._try_resolve_remote_state()
        self.assertEqual(storage2['client_data']['trade_key_counter'], 5)
        # the remote state is resolved now, so publishing becomes safe
        self.assertTrue(restorer._publish_allowed)
        # publishing after the restore must outrank the restored backup on the relays
        restorer._maybe_publish_backup()
        published = restorer.nostr_worker.replaceable_events[-1]
        restored_ts = backup._decrypt_payload(
            backup.nostr_worker.replaceable_events[-1]['content'])['timestamp']
        self.assertGreater(published['created_at'], restored_ts)

    async def test_publish_blocked_until_remote_state_resolved(self):
        original_timeout = escrow_constants.BACKUP_FETCH_TIMEOUT_SEC
        escrow_constants.BACKUP_FETCH_TIMEOUT_SEC = 0.2
        self.addCleanup(setattr, escrow_constants, 'BACKUP_FETCH_TIMEOUT_SEC', original_timeout)

        # the fetch job dies without serving anything (e.g. relays unreachable): we must
        # not consider publishing safe, the relays might still hold a recoverable backup.
        # This holds even when local state exists, e.g. created while relays were down
        # or restored from an old wallet file copy.
        wallet = MockWallet()
        backup = self.make_backup_worker(wallet, {'client_data': {'trade_key_counter': 1}})
        await backup._try_resolve_remote_state()
        self.assertFalse(backup._publish_allowed)
        self.assertGreater(backup._next_remote_resolve, 0)  # retry scheduled with backoff

        # a subscription surviving the full fetch window without results is conclusive:
        # no backup exists, publishing is safe
        backup2 = self.make_backup_worker(MockWallet(), {})
        backup2.nostr_worker.fetch_jobs_die = False
        await backup2._try_resolve_remote_state()
        self.assertTrue(backup2._publish_allowed)

    async def test_unreadable_backup_blocks_publishing(self):
        original_timeout = escrow_constants.BACKUP_FETCH_TIMEOUT_SEC
        escrow_constants.BACKUP_FETCH_TIMEOUT_SEC = 0.2
        self.addCleanup(setattr, escrow_constants, 'BACKUP_FETCH_TIMEOUT_SEC', original_timeout)
        # the relays hold an authenticated backup from a newer plugin version: it must
        # never be replaced, so publishing stays disabled even though the fetch window
        # passed without a usable backup
        wallet = MockWallet()
        storage = {'client_data': {'trade_key_counter': 1}}
        backup = self.make_backup_worker(wallet, storage)
        payload = backup._build_payload({'client_data': {}})
        payload['version'] = escrow_constants.BACKUP_VERSION + 1
        event_kwargs = {
            'kind': escrow_constants.BACKUP_EVENT_KIND,
            'content': backup._encrypt_payload(payload),
            'd_tag': backup._d_tag(),
            'signing_key': backup._backup_key,
        }
        restorer, _storage2 = self.make_restore_target(wallet, [event_kwargs])
        restorer.nostr_worker.fetch_jobs_die = False
        await restorer._try_resolve_remote_state()
        self.assertFalse(restorer._publish_allowed)

    async def test_fresh_wallets_use_random_trade_key_offsets(self):
        # a wallet trading before its old backup was recovered must not reuse the
        # key ids of its previous life (the merged states would share trade keys)
        first_ids = set()
        for _i in range(2):
            client = EscrowClient(MockWallet(), MockNostrWorker(), storage={})
            self.addCleanup(client.stop)
            client.get_new_privkey_for_trade()
            first_ids.add(client.storage['trade_key_counter'])
        self.assertEqual(2, len(first_ids))

    async def test_backup_key_derivation(self):
        wallet = MockWallet()
        backup_key = NostrStateBackup.get_backup_privkey_for_wallet(wallet)
        # deterministic, and distinct from the identity and per-trade keys
        self.assertEqual(backup_key.hex(), NostrStateBackup.get_backup_privkey_for_wallet(wallet).hex())
        identity = EscrowWorker.get_nostr_privkey_for_wallet(wallet)
        trade0 = EscrowWorker.get_nostr_privkey_for_wallet(wallet, key_id=0)
        self.assertEqual(3, len({backup_key.hex(), identity.hex(), trade0.hex()}))
        # a different wallet derives a different backup key
        self.assertNotEqual(
            backup_key.hex(), NostrStateBackup.get_backup_privkey_for_wallet(MockWallet()).hex())

    async def test_oversized_backup_prunes_finished_trades(self):
        wallet = MockWallet()
        storage = {'client_data': {'escrow_client_trades': {}, 'trade_key_counter': 1}}
        trades = storage['client_data']['escrow_client_trades']
        agent_pubkey = PrivateKey().public_key.hex()
        ongoing_id = 'ff' * 32
        for i in range(5):
            contract = make_contract(agent_pubkey)
            contract.text = f'{i}' * 1500
            is_last = i == 4
            trades[ongoing_id if is_last else f'{i:02d}' * 16] = ClientEscrowTrade(
                state=TradeState.ONGOING if is_last else TradeState.FINISHED,
                contract=contract,
                is_maker=True,
                onchain_fallback_address=make_address(),
                creation_timestamp=1000 + i,
            )
        original_limit = escrow_constants.MAX_BACKUP_EVENT_BYTES
        escrow_constants.MAX_BACKUP_EVENT_BYTES = 6000
        self.addCleanup(setattr, escrow_constants, 'MAX_BACKUP_EVENT_BYTES', original_limit)

        backup = self.make_backup_worker(wallet, storage)
        backup._maybe_publish_backup()
        event_kwargs = backup.nostr_worker.replaceable_events[-1]
        self.assertLessEqual(len(event_kwargs['content']), 6000)
        kept = backup._decrypt_payload(event_kwargs['content'])['data']['client_data']['escrow_client_trades']
        # ongoing trades are never pruned, the oldest finished trades are dropped first
        self.assertIn(ongoing_id, kept)
        self.assertNotIn('00' * 16, kept)
        self.assertLess(len(kept), 5)
        # the local state is untouched by the pruning
        self.assertEqual(5, len(trades))

    async def test_meaningful_state_detection(self):
        has_state = NostrStateBackup._has_meaningful_state
        self.assertFalse(has_state({}))
        # the empty skeleton the workers create on startup is not meaningful
        self.assertFalse(has_state({
            'client_data': {'escrow_client_trades': {}},
            'agent_data': {'escrow_agent_trades': {}, 'pending_lightning_invoices': {}},
        }))
        self.assertTrue(has_state({'is_escrow_agent': True}))
        self.assertTrue(has_state({'client_data': {'trade_key_counter': 0}}))
        self.assertTrue(has_state({'client_data': {'agents': ['ab' * 32]}}))
        self.assertTrue(has_state({'agent_data': {'profile': {'name': 'x'}}}))
        self.assertTrue(has_state({'client_data': {'escrow_client_trades': {'a': {}}}}))


class TestPersistence(ElectrumTestCase):

    async def test_stored_trades_roundtrip_with_patches(self):
        db = JsonDB('', encoder=MyEncoder)
        db.data['plugin_data'] = {}
        db.data['plugin_data']['escrow'] = {}
        db.data['plugin_data']['escrow']['agent_data'] = {}
        db.data['plugin_data']['escrow']['agent_data']['escrow_agent_trades'] = {}
        trades = db.data['plugin_data']['escrow']['agent_data']['escrow_agent_trades']

        contract = make_contract('ab' * 32)
        trade = AgentEscrowTrade(
            state=TradeState.WAITING_FOR_TAKER,
            trade_participants=TradeParticipants(maker=TradeParticipant(
                pubkey='cd' * 32, funding_request_key='k1',
                onchain_fallback_address=make_address(), contract_signature='s1')),
            contract=contract,
        )
        trades['tid1'] = trade
        db.pending_changes.clear()

        # nested attribute mutations must generate db patches
        trade.state = TradeState.ONGOING
        trade.trade_participants.maker.confirmed = True
        trade.trade_participants.taker = TradeParticipant(
            pubkey='ef' * 32, funding_request_key='k2',
            onchain_fallback_address=make_address(), contract_signature='s2')
        trade.trade_participants.taker.payout_due_sat = 1234
        self.assertEqual(len(db.pending_changes), 4)

        # values survive a serialization roundtrip with correct types
        db2 = JsonDB(db.dump(human_readable=False), encoder=MyEncoder)
        trade2 = db2.data['plugin_data']['escrow']['agent_data']['escrow_agent_trades']['tid1']
        self.assertIsInstance(trade2, AgentEscrowTrade)
        self.assertEqual(trade2.state, TradeState.ONGOING)
        self.assertIsInstance(trade2.contract, TradeContract)
        self.assertEqual(trade2.contract.contract_hash(), contract.contract_hash())
        self.assertEqual(trade2.trade_participants.taker.payout_due_sat, 1234)
        # and mutations after reloading also generate patches
        trade2.trade_participants.taker.payout_paid = True
        self.assertTrue(any('payout_paid' in p for p in db2.pending_changes))

    async def test_client_trade_roundtrip(self):
        db = JsonDB('', encoder=MyEncoder)
        db.data['plugin_data'] = {}
        db.data['plugin_data']['escrow'] = {}
        db.data['plugin_data']['escrow']['client_data'] = {}
        db.data['plugin_data']['escrow']['client_data']['escrow_client_trades'] = {}
        trades = db.data['plugin_data']['escrow']['client_data']['escrow_client_trades']

        trade = ClientEscrowTrade(
            state=TradeState.ONGOING,
            contract=make_contract('ab' * 32),
            is_maker=False,
            onchain_fallback_address=make_address(),
            private_key_hex='11' * 32,
        )
        trades['tid'] = trade
        trade.payout_due_sat = 99
        trade.postbox_key = 'trade1xyz'

        db2 = JsonDB(db.dump(human_readable=False), encoder=MyEncoder)
        trade2 = db2.data['plugin_data']['escrow']['client_data']['escrow_client_trades']['tid']
        self.assertIsInstance(trade2, ClientEscrowTrade)
        self.assertEqual(trade2.payout_due_sat, 99)
        self.assertEqual(trade2.postbox_key, 'trade1xyz')
        self.assertEqual(trade2.private_key.hex(), '11' * 32)
        self.assertEqual(trade2.payment_direction, TradePaymentDirection.RECEIVING)
