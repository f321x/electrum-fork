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
from electrum.util import MyEncoder
from electrum_ecc import ECPrivkey
from electrum_aionostr.key import PrivateKey

from electrum.plugins.escrow.agent import (
    EscrowAgent, AgentEscrowTrade, TradeParticipant, TradeParticipants,
)
from electrum.plugins.escrow.client import EscrowClient, ClientEscrowTrade
from electrum.plugins.escrow.escrow_worker import (
    TradeContract, EscrowAgentProfile, EscrowWorker, NOSTR_KEY_FAMILY_ESCROW,
)
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

    def send_encrypted_ephemeral_message(self, *, cleartext_content, recipient_pubkey,
                                         signing_key, response_to_id=None):
        self.ephemeral_messages.append((cleartext_content, recipient_pubkey, response_to_id))

    def send_encrypted_direct_message(self, *, cleartext_content, recipient_pubkey,
                                      expiration_duration, signing_key) -> str:
        self.dms.append((cleartext_content, recipient_pubkey))
        return 'dm_event_id'

    def broadcast_agent_profile_event(self, **kwargs):
        self.broadcasts.append(kwargs)

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

    def make_agent(self) -> EscrowAgent:
        wallet = MockWallet()
        nostr = MockNostrWorker()
        agent = EscrowAgent(wallet, nostr, storage={})
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
