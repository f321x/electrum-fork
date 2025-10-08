import logging
import os
import time

import electrum.trampoline
from . import ElectrumTestCase
from .test_lnchannel import create_test_channels

from electrum.lnutil import RECEIVED, MIN_FINAL_CLTV_DELTA_ACCEPTED, LnFeatures
from electrum.lntransport import LNPeerAddr
from electrum.logging import console_stderr_handler
from electrum.invoices import LN_EXPIRY_NEVER, PR_UNPAID
from electrum.bolt12 import BOLT12InvoicePathIDPayload
from electrum.lnworker import LNWALLET_FEATURES
from electrum.crypto import sha256


class TestLNWallet(ElectrumTestCase):
    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    async def asyncSetUp(self):
        self.lnwallet_anchors = self.create_mock_lnwallet(name='mock_lnwallet_anchors', has_anchors=True)
        await super().asyncSetUp()

    def test_create_payment_info(self):
        wallet = self.lnwallet_anchors
        tests = (
            (100_000, 200, 100),
            (None, 200, 100),
            (None, None, LN_EXPIRY_NEVER),
            (100_000, None, 0),
        )
        for amount_msat, min_final_cltv_delta, exp_delay in tests:
            payment_hash = wallet.create_payment_info(
                amount_msat=amount_msat,
                min_final_cltv_delta=min_final_cltv_delta,
                exp_delay=exp_delay,
            )
            self.assertIsNotNone(wallet.get_preimage(payment_hash))
            pi = wallet.get_payment_info(payment_hash, direction=RECEIVED)
            self.assertEqual(pi.amount_msat, amount_msat)
            self.assertEqual(pi.min_final_cltv_delta, min_final_cltv_delta or MIN_FINAL_CLTV_DELTA_ACCEPTED)
            self.assertEqual(pi.expiry_delay, exp_delay or LN_EXPIRY_NEVER)
            self.assertEqual(pi.db_key, f"{payment_hash.hex()}:{int(pi.direction)}")
            self.assertEqual(pi.status, PR_UNPAID)
        self.assertIsNone(wallet.get_payment_info(os.urandom(32), direction=RECEIVED))

    def test_create_payment_info__amount_must_not_be_zero(self):
        wallet = self.lnwallet_anchors
        amount_msat, min_final_cltv_delta, exp_delay = (0, 200, 100)
        with self.assertRaises(ValueError):
            wallet.create_payment_info(
                amount_msat=amount_msat,
                min_final_cltv_delta=min_final_cltv_delta,
                exp_delay=exp_delay,
            )

    def test_save_blinded_payment_info(self):
        amount_msat = 1000
        created_at = int(time.time())
        relative_expiry = created_at + 100
        payment_preimage = os.urandom(32)
        min_final_cltv_expiry_delta = 322
        invoice_features = LNWALLET_FEATURES.for_invoice()
        invreq_payer_id = os.urandom(33)
        path_id_payload = BOLT12InvoicePathIDPayload(
            amount_msat=amount_msat,
            created_at=created_at,
            relative_expiry=relative_expiry,
            payment_preimage=payment_preimage,
            min_final_cltv_expiry_delta=min_final_cltv_expiry_delta,
            invoice_features=invoice_features,
            payer_id=invreq_payer_id,
        )
        wallet = self.lnwallet_anchors
        wallet.save_blinded_payment_info(path_id_payload)
        payment_hash = sha256(payment_preimage)
        payment_info = wallet.get_payment_info(payment_hash, direction=RECEIVED)
        self.assertIsNotNone(payment_info)
        self.assertEqual(wallet.get_preimage(payment_hash), payment_preimage)
        self.assertEqual(payment_info.payment_hash, payment_hash)
        self.assertEqual(payment_info.amount_msat, amount_msat)
        self.assertEqual(payment_info.status, PR_UNPAID)
        self.assertEqual(payment_info.min_final_cltv_delta, min_final_cltv_expiry_delta)
        self.assertEqual(payment_info.expiry_delay, relative_expiry)
        self.assertEqual(payment_info.creation_ts, created_at)
        self.assertEqual(payment_info.invoice_features, invoice_features)

    async def test_trampoline_invoice_features_and_routing_hints(self):
        """
        When the invoice_features signal trampoline support, routing hints must only
        contain trampoline nodes. When it does not, all channel can be added as r_tags.
        We only signal trampoline support in the invoice if all open channels do support trampoline.
        """
        wallet = self.lnwallet_anchors
        self.assertFalse(wallet.uses_trampoline())

        trampoline_peer = self.create_mock_lnwallet(name='trampoline_peer', has_anchors=True)
        trampoline_pubkey = trampoline_peer.node_keypair.pubkey

        regular_peer = self.create_mock_lnwallet(name='regular_peer', has_anchors=True)
        regular_pubkey = regular_peer.node_keypair.pubkey

        chan_t, _ = create_test_channels(alice_lnwallet=wallet, bob_lnwallet=trampoline_peer, anchor_outputs=True)
        chan_r, _ = create_test_channels(alice_lnwallet=wallet, bob_lnwallet=regular_peer, anchor_outputs=True)
        wallet._add_channel(chan_t)
        wallet._add_channel(chan_r)

        # only trampoline_peer is a known trampoline forwarder
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            'trampoline_peer': LNPeerAddr(
                host="127.0.0.1",
                port=9735,
                pubkey=trampoline_pubkey,
            ),
        }
        self.addCleanup(lambda: electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS.clear())

        amount_msat = 100_000

        # mixed peers: trampoline feature must be stripped, all peers in hints
        payment_hash = wallet.create_payment_info(amount_msat=amount_msat)
        pi = wallet.get_payment_info(payment_hash, direction=RECEIVED)
        self.assertFalse(
            pi.invoice_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM),
            "trampoline bit should be stripped when not all peers are trampoline",
        )

        lnaddr, _ = wallet.get_bolt11_invoice(payment_info=pi, message='test', fallback_address=None)
        hint_node_ids = {route[0][0] for route in lnaddr.get_routing_info('r')}
        self.assertEqual(hint_node_ids, {trampoline_pubkey, regular_pubkey})

        # trampoline feature should not be set if we use trampoline but one peer is not a trampoline
        old_check, wallet.uses_trampoline = wallet.uses_trampoline, lambda: True
        self.assertTrue(wallet.uses_trampoline())

        payment_hash = wallet.create_payment_info(amount_msat=amount_msat)
        pi = wallet.get_payment_info(payment_hash, direction=RECEIVED)
        self.assertFalse(
            pi.invoice_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM),
            "trampoline feature should not be set if we use trampoline but one peer is not a trampoline",
        )

        wallet.clear_invoices_cache()
        lnaddr, _ = wallet.get_bolt11_invoice(payment_info=pi, message='test', fallback_address=None)
        hint_node_ids = {route[0][0] for route in lnaddr.get_routing_info('r')}
        self.assertEqual(hint_node_ids, {trampoline_pubkey, regular_pubkey})

        wallet.uses_trampoline = old_check
        self.assertFalse(wallet.uses_trampoline())

        # all peers trampoline: we signal trampoline support, even with trampoline disabled
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS['regular_peer'] = LNPeerAddr(
            host="127.0.0.1",
            port=9735,
            pubkey=regular_pubkey,
        )

        payment_hash2 = wallet.create_payment_info(amount_msat=amount_msat)
        pi2 = wallet.get_payment_info(payment_hash2, direction=RECEIVED)
        self.assertTrue(
            pi2.invoice_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM),
            "trampoline bit should be present when all peers are trampoline",
        )

        wallet.clear_invoices_cache()
        lnaddr2, _ = wallet.get_bolt11_invoice(payment_info=pi2, message='test', fallback_address=None)
        hint_node_ids2 = {route[0][0] for route in lnaddr2.get_routing_info('r')}
        self.assertEqual(hint_node_ids2, {trampoline_pubkey, regular_pubkey})

        # assert only trampoline peers are included in r_tags if the invoice_features signal trampoline
        del electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS['regular_peer']
        wallet.clear_invoices_cache()
        lnaddr3, _ = wallet.get_bolt11_invoice(payment_info=pi2, message='test', fallback_address=None)
        hint_node_ids3 = {route[0][0] for route in lnaddr3.get_routing_info('r')}
        self.assertEqual(hint_node_ids3, {trampoline_pubkey})
