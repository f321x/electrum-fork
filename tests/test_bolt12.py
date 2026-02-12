import asyncio
import copy
import io
import os
import time
import json
from pathlib import Path

from electrum_ecc import ECPrivkey

from electrum import segwit_addr, lnutil
from electrum import bolt12
from electrum.bolt12 import (
    is_offer, decode_offer, encode_invoice_request, decode_invoice_request, encode_invoice, decode_invoice,
    encode_offer, verify_request_and_create_invoice, InvoiceRequestException, bolt12_bech32_to_bytes
)
from electrum.crypto import privkey_to_pubkey
from electrum.invoices import LN_EXPIRY_NEVER
from electrum.lnchannel import Channel
from electrum.lnmsg import UnknownMandatoryTLVRecordType, _tlv_merkle_root, OnionWireSerializer
from electrum.lnonion import OnionHopsDataSingle
from electrum.lnutil import LnFeatures
from electrum.onion_message import NoRouteBlindingChannelPeers
from electrum.segwit_addr import INVALID_BECH32, bech32_encode, Encoding, convertbits
from electrum.util import bfh

from . import ElectrumTestCase, test_lnpeer
from .test_lnpeer import PeerInTests, PutIntoOthersQueueTransport


def bech32_decode(x):
    return segwit_addr.bech32_decode(x, ignore_long_length=True, with_checksum=False)


class MockLNWallet(test_lnpeer.MockLNWallet):
    def __init__(self):
        lnkey = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        kp = lnutil.Keypair(privkey_to_pubkey(lnkey), lnkey)
        q = asyncio.Queue()
        super().__init__(local_keypair=kp, chans=[], tx_queue=q, name='test', has_anchors=False)

    def create_payment_info(
        self, *,
        amount_msat,
        min_final_cltv_delta=None,
        exp_delay: int = LN_EXPIRY_NEVER,
        write_to_disk=True
    ) -> bytes:
        return b''

    def add_path_ids_for_payment_hash(self, payment_hash, invoice_paths):
        pass


class MockChannel:
    def __init__(self, node_id, rcv_capacity: int = 0):
        self.short_channel_id = lnutil.ShortChannelID.from_str('0x0x0')
        self.node_id = node_id
        self.rcv_capacity = rcv_capacity

    def is_active(self):
        return True

    def can_receive(self, *, amount_msat, check_frozen=False):
        return True if self.rcv_capacity == 0 else amount_msat <= self.rcv_capacity

    def get_remote_update(self):
        return bfh('0102beb6d231566566e014c6f417f247a5e8e882fd6b44ff4526ee230ace401d6ae57205b5c5dd2de21b9ceecbd8676d99a4588266b38b8af59305103c956127122843497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea3309000000002fe34de423b66e0a6510eb91030200900000000000000001000003e8000000640000000012088038')


ROUTE_BLINDING_CAPABLE_PEER_FEATURES = LnFeatures(LnFeatures.OPTION_ROUTE_BLINDING_OPT)


class MockPeer(PeerInTests):
    def __init__(self, lnwallet, pubkey, wkp, their_features=ROUTE_BLINDING_CAPABLE_PEER_FEATURES):
        transport = PutIntoOthersQueueTransport(name='a', keypair=wkp)
        super().__init__(lnwallet, pubkey, transport)
        self.their_features = their_features

    async def wait_one_htlc_switch_iteration(self, *args):
        pass


class TestBolt12(ElectrumTestCase):

    def test_bolt12_bech32_to_bytes(self):
        valid_bolt12_strings = (
            ("lno1pqpzacq2qqgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3up5nwlwchur9zukwx743mvm0rvftrhskna22pcvtkyhufn5rc97j3gzqffs859lkadpfasgwxj47xvml7jgekez0lpfuwzhegyxsn2lzdx86qpny7xrmgwj6lphxcfauu22kenqnty4tqdlgnh8tyg87lamqe84nmh2vn0a2n908l7z7cfjghjsuusv7k079upfw0x7dpzavqpwj8swx9ee9q9cumg07fk4gvlajyhy6lfjv0cfe9gqxg0gykehtgjkxwzz24rqdssj4fjcm8xhv2rwel04ed4up2h5sf8n6y7scr0q5rt65k06s6u3mvefzer7qq",
             "08022ee00a0010ee03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f0349bbeec5f8328b9671bd58ed9b78d8958ef0b4faa5070c5d897e26741e0be94502025303d0bfb75a14f60871a55f199bffa48cdb227fc29e3857ca08684d5f134c7d0033278c3da1d2d7c373613de714ab66609ac95581bf44ee759107f7fbb064f59eeea64dfd54caf3ffc2f613245e50e720cf59fe2f02973cde6845d6002e91e0e31739280b8e6d0ff26d5433fd912e4d7d3263f09c9500321e825b375a25633842554606c212aa658d9cd76286ecfdf5cb6bc0aaf4824f3d13d0c0de0a0d7aa59fa86b91db3291647e00"),
            ("lno1pqpzacq2qqgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3uprukkghkdufdz6adxl0ejhy0lmzfykj08u6df9v4v2c93qknz8eggzq2jyyszrrt35mmkyl7efrv5x8a3wspk07pghey4a5kcm4ef76p0ksqpnh7fqgmq9eaf7ntqspcksqkqk8ngvjtjp585mqw3qata3xe8aycgkpprk87yqcxhh705dxauxkghsc9xywqpez7lt5gw67kqwejl83unmuc7r44h32durffs4rmpcgrhxa8x8y9gqxgy9w2tqgpxqk0tl487a9ssuchyh5p9t3le3n5ylhevggk6ly8wzxvds0jawct4spe2tzqfp5d34kah9ss",
             "08022ee00a0010ee03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f023e5ac8bd9bc4b45aeb4df7e65723ffb1249693cfcd35256558ac1620b4c47ca10202a44240431ae34deec4ffb291b2863f62e806cff0517c92bda5b1bae53ed05f680033bf92046c05cf53e9ac100e2d0058163cd0c92e41a1e9b03a20eafb1364fd26116084763f880c1af7f3e8d37786b22f0c14c47003917beba21daf580eccbe78f27be63c3ad6f1537834a6151ec3840ee6e9cc7215003208572960404c0b3d7fa9fdd2c21cc5c97a04ab8ff319d09fbe58845b5f21dc2331b07cbaec2eb00e54b10121a3635b76e584"),
            ("lno1qsgve2uaxjsvf885prfgawzf6d09vzsqpczxnzdgesgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upc0taarq42pfspgzxdytktyf8jmx8symyy4p3w6wr26m3c3l3munszqwpuu8l2fxnf0awqf3fq069lw2ple9zlxuqx0whmxnl6sjavs98h6qpngsrfw245mh995tw4qlkh87ulgg00fm8p90s70sslvm23yv77qk6e70dq6a9c5fa9qg74w8gpfd2tqs3eavpaedey0agxmzacdrcd9vwrmgjemeym4ge0p5unp66tkz47wh7x4asqxtv35cx0sc23qkgt27az82w7n6tngn4r9wzuam3ztpps7q3sd60d42dltr37gagfy2asevymltrchy43zgtzzq68dcmv6rprk4yzfv4wl65vw6q2uz8tzc0d40v4ltdcuwnw9t3eyq",
             "0410ccab9d34a0c49cf408d28eb849d35e560a000e046989a8cc10ee03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f0387afbd182aa0a601408cd22ecb224f2d98f026c84a862ed386ad6e388fe3be4e020383ce1fea49a697f5c04c5207e8bf7283fc945f370067bafb34ffa84bac814f7d00334406972ab4ddca5a2dd507ed73fb9f421ef4ece12be1e7c21f66d51233de05b59f3da0d74b8a27a5023d571d014b54b04239eb03dcb7247f506d8bb868f0d2b1c3da259de49baa32f0d3930eb4bb0abe75fc6af60032d91a60cf861510590b57ba23a9de9e97344ea32b85ceee2258430f02306e9edaa9bf58e3e4750922bb0cb09bfac78b92b112162103476e36cd0c23b54824b2aefea8c7680ae08eb161edabd95fadb8e3a6e2ae3920"),
            ("lno1pqpq05q2qqgwuquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upgkdz0l3yd0yt3u9kmp5cg6kfw65kh0n0q9m022xe8y0mq69wmm9gzq0ckt2qqs73uyx2pe3tcmrhf7hszkh3393gwc420x2uew4846tgk5qpn0clyjyaa0cfxc9ryff0qfx48wv8u65w4a7fxfsqeln9ahjz9qcf0t0umrgxnzcly4es6ct97ddjcvgcehvpc09sqwsjc0cusxrwvx44j62pskt9t75ex5px84294a48c0h5jx8gqx20wkjusrgktsa53c23ksrhpuncrmdvetfjhdpgmnu9tej3m9nlm9m9tzhnl39mje2gxdsu2zlejvp63xy",
             "080207d00a0010ee03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f028b344ffc48d79171e16db0d308d592ed52d77cde02edea51b2723f60d15dbd950203f165a80087a3c21941cc578d8ee9f5e02b5e312c50ec554f32b99754f5d2d16a00337e3e4913bd7e126c14644a5e049aa7730fcd51d5ef9264c019fccbdbc8450612f5bf9b1a0d3163e4ae61ac2cbe6b65862319bb03879600742587e39030dcc356b2d2830b2cabf5326a04c7aa8b5ed4f87de9231d00329eeb4b901a2cb87691c2a3680ee1e4f03db5995a6576851b9f0abcca3b2cffb2ecab15e7f89772ca9066c38a17f326075131")
        )
        for bolt12_str, expected_bytes_hex in valid_bolt12_strings:
            result = bolt12_bech32_to_bytes(bolt12_str)
            self.assertEqual(result.hex(), expected_bytes_hex)

    def test_bolt12_string_formatting(self):
        """
        Test if we handle string formatting according to bolt 12 using the format-string-test.json
        test vector.
        https://github.com/lightning/bolts/blob/5f31faa0b6e2cdbe32171d79464305f90bda9585/bolt12/format-string-test.json
        """
        with open(Path(__file__).parent / 'bolt12_format_string_test.json', 'r') as f:
            tests = json.load(f)
        for test in tests:
            valid, string, msg = test['valid'], test['string'], f"{test['comment']}: {test['string']}"
            if valid:
                self.assertTrue(is_offer(string), msg=msg)
                result = decode_offer(string)
                self.assertIsInstance(result, dict)
            else:
                self.assertFalse(is_offer(string), msg=msg)
                with self.assertRaises(ValueError, msg=msg):
                    decode_offer(string)

    def test_decode(self):
        # https://bootstrap.bolt12.org/examples
        offer = 'lno1pg257enxv4ezqcneype82um50ynhxgrwdajx293pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmc'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        self.assertTrue(is_offer(offer))
        od = decode_offer(offer)
        self.assertEqual(od, {'offer_description': {'description': "Offer by rusty's node"},
                              'offer_issuer_id':
                                  {'id': bfh('023f3219da03ee29a12de4107e6c5c364f607382f065f2bfed91ddd6b91079bfbc')}
                              })

        offer = 'lno1pqqnyzsmx5cx6umpwssx6atvw35j6ut4v9h8g6t50ysx7enxv4epyrmjw4ehgcm0wfczucm0d5hxzag5qqtzzq3lxgva5qlw9xsjmeqs0ek9cdj0vpec9ur972l7mywa66u3q7dlhs'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        od = decode_offer(offer)
        self.assertEqual(od, {'offer_amount': {'amount': 50},
                              'offer_description': {'description': '50msat multi-quantity offer'},
                              'offer_issuer': {'issuer': 'rustcorp.com.au'},
                              'offer_quantity_max': {'max': 0},
                              'offer_issuer_id':
                                  {'id': bfh('023f3219da03ee29a12de4107e6c5c364f607382f065f2bfed91ddd6b91079bfbc')}
                              })

        # TODO: tests below use recurrence (tlv record type 26) which is not supported/generated from wire specs
        # (c-lightning carries patches re-adding these, but for now we ignore them)

        offer = 'lno1pqqkgzs5xycrqmtnv96zqetkv4e8jgrdd9h82ar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqq7q'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqqkgz38xycrqmtnv96zqetkv4e8jgrdd9h82ar99ss82upqw3hjqargwfjk2gr5d9kk2ucjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qsq8s0qzqs'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqqkgz3zxycrqmtnv96zqetkv4e8jgryv9ujcgrxwfhk6gp3949xzm3dxgcryvgjzpe82um50yhx77nvv938xtn0wfn3vggz8uepnksrac56zt0yzplxchpkfas88qhsvhetlmv3mhttjyreh77p5qspqysq2q2laenqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqpq86q2fgcnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qcteyqcksu3qvfjkvmmjv5s8gmeqxcczqum9vdhkuernypkxzar9zgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pcpsqqq8pqqpuyqzszhlwvcqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1pqpq86q2xycnqvpsd4ekzapqv4mx2uneyqcnqgryv9uhxtpqveex7mfqxyk55ctw95erqv339ss8qun094exzarpzgg8yatnw3ujumm6d3skyuewdaexw93pqglnyxw6q0hzngfdusg8umzuxe8kquuz7pjl90ldj8wadwgs0xlmcxszqy9pczqqp5hsqqgd9uqzqpgptlhxvqq'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

        offer = 'lno1qcp4256ypqpq86q2pucnq42ngssx2an9wfujqerp0yfpqun4wd68jtn00fkxzcnn9ehhyeckyypr7vsemgp7u2dp9hjpqlnvtsmy7crnstcxtu4lakgam44ezpuml0q6qgqsz'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        # contains TLV record type 26 which is not defined (yet) in 12-offer-encoding.md
        with self.assertRaises(UnknownMandatoryTLVRecordType):
            od = bolt12.decode_offer(offer)

    def test_decode_offer(self):
        offer = 'lno1pggxv6tjwd6zqar9wd6zqmmxvejhy93pq02rpdcl6l20pakl2ad70k0n8v862jwp2twq8a8uz0hz5wfafg495'
        d = bech32_decode(offer)
        self.assertNotEqual(d, INVALID_BECH32, "bech32 decode error")
        self.assertEqual(d.hrp, 'lno', "wrong hrp")
        self.assertTrue(is_offer(offer))

        od = decode_offer(offer)
        self.assertEqual(od['offer_description']['description'], 'first test offer')
        self.assertEqual(od['offer_issuer_id']['id'], bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a'))

    def test_decode_invreq(self):
        payer_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        kp = lnutil.Keypair(privkey_to_pubkey(payer_key), payer_key)

        invreq_tlv = bfh('0a1066697273742074657374206f66666572162103d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a520215b358210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c591b696e7672657120666f722066697273742074657374206f66666572f04080ffce74cb03393cd47307de79d7a6782e0d7b84b76d29958f9f732369a6620e0ed6bbeee66c99d077eb62f8cec8e2fe06ab15943961b2c009e41781aca3f34e')
        invreq = decode_invoice_request(invreq_tlv)

        data = {
            'offer_description': {'description': 'first test offer'},
            'offer_issuer_id': {'id': bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a')},
            'invreq_amount': {'msat': 5555},
            'invreq_payer_note': {'note': 'invreq for first test offer'},
            'invreq_payer_id': {'key': kp.pubkey},
        }
        del invreq['signature']
        self.assertEqual(invreq, data)

    def test_decode_invoice(self):
        signing_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        kp = lnutil.Keypair(privkey_to_pubkey(signing_key), signing_key)

        invoice_tlv = bfh('0407010203040506070801010a13746573745f656e636f64655f696e766f696365b02102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f04088d62f8db0c4033f7c4700e050f298d93f2d28a67e015f675c0835e22bfae2ec82fae6f404b24a92dc4779b85ff1fd63ff0521284e78f24969039ad98c0204ab')
        invoice = decode_invoice(invoice_tlv)
        data = {'offer_metadata': {'data': bfh('01020304050607')},
                'offer_amount': {'amount': 1},
                'offer_description': {'description': 'test_encode_invoice'},
                'invoice_node_id': {'node_id': kp.pubkey},
        }
        del invoice['signature']
        self.assertEqual(invoice, data)

    def test_encode_offer(self):
        data = {
            'offer_description': {'description': 'first test offer'},
            'offer_issuer_id': {'id': bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a')}
        }
        offer_tlv = encode_offer(data)
        self.assertEqual(offer_tlv, bfh('0a1066697273742074657374206f66666572162103d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a'))
        offer_tlv_5bit = convertbits(list(offer_tlv), 8, 5)
        bech32_offer = bech32_encode(Encoding.BECH32, 'lno', offer_tlv_5bit, with_checksum=False)
        self.assertEqual(bech32_offer, 'lno1pggxv6tjwd6zqar9wd6zqmmxvejhy93pq02rpdcl6l20pakl2ad70k0n8v862jwp2twq8a8uz0hz5wfafg495')

    def test_encode_invreq(self):
        payer_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        kp = lnutil.Keypair(privkey_to_pubkey(payer_key), payer_key)

        data = {
            'offer_description': {'description': 'first test offer'},
            'offer_issuer_id': {'id': bfh('03d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a')},
            'invreq_amount': {'msat': 5555},
            'invreq_payer_note': {'note': 'invreq for first test offer'},
            'invreq_payer_id': {'key': kp.pubkey},
        }
        invreq_tlv = encode_invoice_request(data, payer_key)
        self.assertEqual(invreq_tlv, bfh('0a1066697273742074657374206f66666572162103d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5a520215b358210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c591b696e7672657120666f722066697273742074657374206f66666572f04080ffce74cb03393cd47307de79d7a6782e0d7b84b76d29958f9f732369a6620e0ed6bbeee66c99d077eb62f8cec8e2fe06ab15943961b2c009e41781aca3f34e'))

    def test_encode_invoice(self):
        signing_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        kp = lnutil.Keypair(privkey_to_pubkey(signing_key), signing_key)

        data = {'offer_metadata': {'data': bfh('01020304050607')},
                'offer_amount': {'amount': 1},
                'offer_description': {'description': 'test_encode_invoice'},
                'invoice_node_id': {'node_id': kp.pubkey}
        }
        invoice_tlv = encode_invoice(data, signing_key=kp.privkey)
        self.assertEqual(invoice_tlv, bfh('0407010203040506070801010a13746573745f656e636f64655f696e766f696365b02102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f04088d62f8db0c4033f7c4700e050f298d93f2d28a67e015f675c0835e22bfae2ec82fae6f404b24a92dc4779b85ff1fd63ff0521284e78f24969039ad98c0204ab'))

    def test_subtype_encode_decode(self):
        offer = 'lno1pggxv6tjwd6zqar9wd6zqmmxvejhy93pq02rpdcl6l20pakl2ad70k0n8v862jwp2twq8a8uz0hz5wfafg495'
        od = decode_offer(offer)
        data = {'offer_issuer_id': od['offer_issuer_id']}
        invreq_pl_tlv = encode_invoice_request(data, payer_key=bfh('4141414141414141414141414141414141414141414141414141414141414141'))

        ohds = OnionHopsDataSingle(tlv_stream_name='onionmsg_tlv',
                                   payload={
                                       'invoice_request': {'invoice_request': invreq_pl_tlv},
                                       'reply_path': {'path': {
                                           'first_node_id': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                           'first_path_key': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                           'num_hops': 2,
                                           'path': [
                                               {'blinded_node_id': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                                'enclen': 5,
                                                'encrypted_recipient_data': bfh('0000000000')},
                                               {'blinded_node_id': bfh('0309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5'),
                                                'enclen': 6,
                                                'encrypted_recipient_data': bfh('001111222233')}
                                           ]
                                       }},
                                   },
                                   blind_fields={'padding': {'padding': b''},
                                                 #'path_id': {'data': bfh('deadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0')}
                                                 }
                                   )

        ohds_b = ohds.to_bytes()

        self.assertEqual(ohds_b, bfh('fd00fd02940309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e50309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5020309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e5000500000000000309d14e515e8ef4ea022787dcda8550edfbd7da6052208d2fc0cc4f7d949558e500060011112222334065162103d430b71fd7d4f0f6df575be7d9f33b0fa549c152dc03f4fc13ee2a393d4a2a5af04078205e3d9d3cf87b743bcad5bca89f12f868ce638fbb4051d9570bac1a79d90ae3650ebcf15603b9349697edf71bf78ecb802aafe146d9118fe387bdb36ed26e0000000000000000000000000000000000000000000000000000000000000000'))

        with io.BytesIO(ohds_b) as fd:
            ohds2 = OnionHopsDataSingle.from_fd(fd, tlv_stream_name='onionmsg_tlv')
            self.assertTrue('invoice_request' in ohds2.payload)  # TODO
            self.assertTrue('reply_path' in ohds2.payload)  # TODO

        # test nested complex types with count > 1
        offer_data = {
            "offer_absolute_expiry": {"seconds_from_epoch": 1763136094},
            "offer_amount": {"amount": 1000},
            "offer_description": {"description": "ABCD"},
            "offer_issuer_id": {"id": bfh("0325c5bc9c9b4fe688e82784f17bc14e81e3f786e9a8c663e9bbec2412af0c0339")},
            "offer_paths": {"paths": [
                {
                    "first_node_id": bfh("02d4ad66692f3e39773a5917d55db2c8b81839425c4489532fd5d166466fce56d4"),
                    "first_path_key": bfh("02b4d2e30315f7a6322fb57ed420ef8f9c541d7331a8b3a086c2692c49209be811"),
                    "num_hops": bytes([2]),  # num_hops is defined as byte, not int
                    "path": [
                        {
                            "blinded_node_id": bfh("034b1da9c0afa084c604f74f839de006d550422facc3b4be83323702892f7f5949"),
                            "enclen": 51,
                            "encrypted_recipient_data": bfh("42f0018dcfe5185602618b718f7aa72b1b97d8e85b97f88b8fdad95b80fd93a21d9a975cf544e8c4b5c2f519bc83bab84bda6b")
                        },
                        {
                            "blinded_node_id": bfh("021a4900c95fcb5ef59284203e005b505d17cdaa066b13134d98930fb4ff1425f4"),
                            "enclen": 50,
                            "encrypted_recipient_data": bfh("9b66a56801a3da6b3149d8b5df0ce9f25df7605b689dd662c40fc5782cbee2786903e83f6827fa52c93af2acdb8e123c72e0")
                        }
                    ]
                },
                {
                    "first_node_id": bfh("031a10cc4d1aea5a59e7888f3eb2f0509e3fc58dae63deff87ba34f217ae419cf7"),
                    "first_path_key": bfh("029a5a12f3b9c0132176ab5347f49486f3d2572aa9d9c3d8ebf622e80a4131f268"),
                    "num_hops": bytes([2]),  # num_hops is defined as byte, not int
                    "path": [
                        {
                            "blinded_node_id": bfh("0250fce42de743a914b821de93c0033713e9b27c8ada26424c0e75c461c1337e1a"),
                            "enclen": 51,
                            "encrypted_recipient_data": bfh("c2e291a9bcf57b57e115d161f49bd8682044bcd11db3adb96ba4d8d99827650aa5691d48c78822c9ae26c446ffa03a41fbc1de")
                        },
                        {
                            "blinded_node_id": bfh("02718474dc3bd8fb42af40c27ff98da911008f4020b90835d4a39ffea084406614"),
                            "enclen": 50,
                            "encrypted_recipient_data": bfh("9b0fc9045ff50ea82babad699c610e14607343dd70ca12dc5575edb28b5673e3660a3eb1b62fd5b6b7d14fd651d5bbee3ad3")
                        }
                    ]
                }
            ]}
        }

        offer = encode_offer(offer_data)
        decoded = decode_offer(offer)
        self.assertEqual(offer_data, decoded)

    def test_merkle_root(self):
        # test vectors in https://github.com/lightning/bolts/pull/798
        tlvs = [
            (1, bfh('010203e8')),
            (2, bfh('02080000010000020003')),
            (3, bfh('03310266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351800000000000000010000000000000002'))
        ]

        self.assertEqual(_tlv_merkle_root(tlvs[:1]), bfh('b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93'))
        self.assertEqual(_tlv_merkle_root(tlvs[:2]), bfh('c3774abbf4815aa54ccaa026bff6581f01f3be5fe814c620a252534f434bc0d1'))
        self.assertEqual(_tlv_merkle_root(tlvs[:3]), bfh('ab2e79b1283b0b31e0b035258de23782df6b89a38cfa7237bde69aed1a658c5d'))

    def test_invoice_request_schnorr_signature(self):
        # use invoice request in https://github.com/lightning/bolts/pull/798 to match test vectors
        invreq = 'lnr1qqyqqqqqqqqqqqqqqcp4256ypqqkgzshgysy6ct5dpjk6ct5d93kzmpq23ex2ct5d9ek293pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpjkppqvjx204vgdzgsqpvcp4mldl3plscny0rt707gvpdh6ndydfacz43euzqhrurageg3n7kafgsek6gz3e9w52parv8gs2hlxzk95tzeswywffxlkeyhml0hh46kndmwf4m6xma3tkq2lu04qz3slje2rfthc89vss'
        data = decode_invoice_request(invreq)
        del data['signature']  # remove signature, we regenerate it

        payer_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        invreq_pl_tlv = encode_invoice_request(data, payer_key)

        self.assertEqual(invreq_pl_tlv, bfh('0008000000000000000006035553440801640a1741204d617468656d61746963616c205472656174697365162102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f28368661958210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1cf040b8f83ea3288cfd6ea510cdb481472575141e8d8744157f98562d162cc1c472526fdb24befefbdebab4dbb726bbd1b7d8aec057f8fa805187e5950d2bbe0e5642'))

    def test_schnorr_signature(self):
        # encode+decode invoice to test signature
        signing_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        signing_pubkey = ECPrivkey(signing_key).get_public_key_bytes()
        invoice_tlv = encode_invoice({
            'offer_amount': {'amount': 1},
            'offer_description': {'description': 'test'},
            'invoice_node_id': {'node_id': signing_pubkey}
        }, signing_key)
        decode_invoice(invoice_tlv)

    def test_serde_complex_fields(self):
        payer_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')

        # test complex field cardinality without explicit count
        invreq = {
            'offer_paths': {'paths': [
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 0,
                 'path': []},
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 0,
                 'path': []},
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 0,
                 'path': []}
            ]}
        }

        invreq_pl_tlv = encode_invoice_request(invreq, payer_key=payer_key)

        with io.BytesIO() as fd:
            f = io.BytesIO(invreq_pl_tlv)
            deser = OnionWireSerializer.read_tlv_stream(fd=f, tlv_stream_name='invoice_request')
            self.assertEqual(len(deser['offer_paths']['paths']), 3)

        # test complex field all members required
        invreq = {
            'offer_paths': {'paths': [
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 0}
            ]}
        }

        # assertRaises on generic Exception used in lnmsg encode/write_tlv_stream makes flake8 complain
        # so work around this for now (TODO: refactor lnmsg generic exceptions)
        #with self.assertRaises(Exception):
        try:
            invreq_pl_tlv = encode_invoice_request(invreq, payer_key=payer_key)
        except Exception as e:
            pass
        else:
            raise Exception('Exception expected')

        # test complex field count matches parameters
        invreq = {
            'offer_paths': {'paths': [
                {'first_node_id': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'first_path_key': bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
                 'num_hops': 1,
                 'path': []}
            ]}
        }

        with self.assertRaises(AssertionError):
            invreq_pl_tlv = encode_invoice_request(invreq, payer_key=payer_key)

    def gen_base_offer_and_invreq(self, wkp, pkp, *, offer_extra: dict = None, invreq_extra: dict = None):
        offer_data = {
            'offer_metadata': {'data': bfh('01')},
            'offer_amount': {'amount': 1000},
            'offer_description': {'description': 'descr'},
            'offer_issuer': {'issuer': 'test'},
            'offer_issuer_id': {'id': wkp.pubkey}
        }
        if offer_extra:
            offer_data.update(offer_extra)

        invreq_data = copy.deepcopy(offer_data)
        invreq_data.update({
            'invreq_metadata': {'blob': bfh('ff')},
            'invreq_payer_id': {'key': pkp.pubkey},
            'signature': {'sig': bfh('00')}  # bogus
        })
        if invreq_extra:
            invreq_data.update(invreq_extra)

        return offer_data, invreq_data

    async def test_invoice_request(self):
        wallet_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        wkp = lnutil.Keypair(privkey_to_pubkey(wallet_key), wallet_key)
        chan_key = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        ckp = lnutil.Keypair(privkey_to_pubkey(chan_key), chan_key)
        payer_key = bfh('4343434343434343434343434343434343434343434343434343434343434343')
        pkp = lnutil.Keypair(privkey_to_pubkey(payer_key), payer_key)

        lnwallet = self.create_mock_lnwallet(name='alice', has_anchors=True)

        chan = MockChannel(ckp.pubkey, 1_000_000)
        lnwallet._channels[ckp.pubkey] = chan
        peer = MockPeer(lnwallet, ckp.pubkey, wkp)

        # base case but without ROUTE_BLINDING capable peers
        with self.assertRaises(NoRouteBlindingChannelPeers):
            offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
            invoice_data = verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        lnwallet.lnpeermgr._peers[ckp.pubkey] = peer

        # base case
        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        invoice_data = verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)
        del invreq_data['signature']
        for key in invreq_data:
            self.assertEqual(invoice_data.get(key), invreq_data.get(key))

        # non matching offer fields in invreq
        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        del invreq_data['offer_metadata']
        with self.assertRaises(InvoiceRequestException):
            verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        invreq_data['offer_metadata'] = {'data': bfh('02')}
        with self.assertRaises(InvoiceRequestException):
            verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        invreq_data['offer_amount'] = {'amount': 1001}
        with self.assertRaises(InvoiceRequestException):
            verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        invreq_data['offer_issuer_id'] = {'id': ckp.pubkey}
        with self.assertRaises(InvoiceRequestException):
            verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        # invreq_metadata mandatory
        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        del invreq_data['invreq_metadata']
        with self.assertRaises(InvoiceRequestException):
            verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        # expiry
        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        invreq_data['offer_absolute_expiry'] = {'seconds_from_epoch': int(time.time()) - 5}
        with self.assertRaises(InvoiceRequestException):
            verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp, offer_extra={
            'offer_absolute_expiry': {'seconds_from_epoch': int(time.time()) + 5}
        })
        invoice_data = verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        # offer/invreq amount matching
        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        invoice_data = verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)
        self.assertEqual(invoice_data.get('invoice_amount').get('msat'), offer_data.get('offer_amount').get('amount'))

        # offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        # del offer_data['offer_amount']
        # del invreq_data['offer_amount']
        # with self.assertRaises(InvoiceRequestException):
        #     verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        # rcv capacity check
        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp,
            offer_extra={'offer_amount': {'amount': 2_000_000}},
            invreq_extra={'invreq_amount': {'msat': 2_000_000}},
        )
        with self.assertRaises(InvoiceRequestException):
            verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)

        # invoice_node_id == offer_issuer_id
        offer_data, invreq_data = self.gen_base_offer_and_invreq(wkp, pkp)
        invoice_data = verify_request_and_create_invoice(lnwallet, offer_data, invreq_data)
        self.assertEqual(invoice_data.get('invoice_node_id').get('node_id'), wkp.pubkey)
