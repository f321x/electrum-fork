from typing import Sequence, Tuple
from unittest import mock

import electrum_ecc as ecc

from electrum import SimpleConfig, bitcoin, descriptor
from electrum.address_synchronizer import AddressSynchronizer, TX_HEIGHT_UNCONFIRMED
from electrum.bitcoin import construct_witness, hash_to_segwit_addr, opcodes
from electrum.script_interpreter import verify_input
from electrum.transaction import Transaction, PartialTransaction, PartialTxInput, PartialTxOutput, TxInput, TxOutpoint
from electrum.util import InvalidTxSignature, UnverifiableTxSignature, TxMinedInfo
from electrum.synchronizer import Synchronizer
from electrum.wallet_db import WalletDB

from . import ElectrumTestCase


KEY_MINE = ecc.ECPrivkey(bytes(31) + b'\x01')
KEY_MINE_2 = ecc.ECPrivkey(bytes(31) + b'\x02')
ADDR_MINE = bitcoin.pubkey_to_address('p2wpkh', KEY_MINE.get_public_key_hex())
ADDR_MINE_2 = bitcoin.pubkey_to_address('p2wpkh', KEY_MINE_2.get_public_key_hex())
ADDR_MINE_P2PKH = bitcoin.pubkey_to_address('p2pkh', KEY_MINE.get_public_key_hex())
ADDR_MINE_P2TR = bitcoin.script_to_address(bitcoin.taproot_output_script(KEY_MINE.get_public_key_bytes()[1:], script_tree=None))
ADDR_OTHER = hash_to_segwit_addr(bytes([1]) * 20, witver=0)


def make_tx(txins: Sequence[TxInput], outputs: Sequence[Tuple[str, int]], *, locktime: int = 0) -> Transaction:
    """Returns a tx with the given inputs, including their scriptSig and witness, and outputs."""
    txins = [PartialTxInput.from_txin(txin, strip_witness=False) for txin in txins]
    txouts = [PartialTxOutput.from_address_and_value(addr, value) for addr, value in outputs]
    return Transaction(PartialTransaction.from_io(txins, txouts, locktime=locktime, BIP69_sort=False).serialize_to_network())


def fund(addr: str, *values: int, n: int = 0) -> Transaction:
    """Returns a tx with an output to addr for each of values. Its input is a coinbase input."""
    txin = TxInput(prevout=TxOutpoint(txid=bytes(32), out_idx=n), script_sig=b'', witness=construct_witness([b'cb']))
    return make_tx([txin], [(addr, value) for value in values])


def spending_psbt(
        parent: Transaction, outputs: Sequence[Tuple[str, int]], *, key=KEY_MINE, script_type: str = 'p2wpkh',
) -> PartialTransaction:
    """Returns an unsigned tx spending output 0 of parent."""
    txin = PartialTxInput(prevout=TxOutpoint(txid=bytes.fromhex(parent.txid()), out_idx=0))
    txin.witness_utxo = parent.outputs()[0]
    txin.script_descriptor = descriptor.get_singlesig_descriptor_from_legacy_leaf(
        pubkey=key.get_public_key_hex(), script_type=script_type)
    txouts = [PartialTxOutput.from_address_and_value(addr, value) for addr, value in outputs]
    return PartialTransaction.from_io([txin], txouts, locktime=0)


def spend(
        parent: Transaction, outputs: Sequence[Tuple[str, int]], *, key=KEY_MINE, script_type: str = 'p2wpkh',
) -> Transaction:
    """Returns a tx signed by key, spending output 0 of parent."""
    tx = spending_psbt(parent, outputs, key=key, script_type=script_type)
    tx.sign({key.get_public_key_bytes(): key.get_secret_bytes()})
    assert tx.is_complete()
    return Transaction(tx.serialize())


def spend_taproot(utxos: Sequence[Tuple[Transaction, int]], outputs: Sequence[Tuple[str, int]]) -> Transaction:
    """Returns a tx spending the given outputs: (parent tx, output index). The inputs that spend a coin of
    ADDR_MINE_P2TR are signed. The others get a witness that is not valid."""
    txins = []
    for parent, out_idx in utxos:
        txin = PartialTxInput(prevout=TxOutpoint(txid=bytes.fromhex(parent.txid()), out_idx=out_idx), script_sig=b'')
        txin.witness_utxo = parent.outputs()[out_idx]
        txins.append(txin)
    txouts = [PartialTxOutput.from_address_and_value(addr, value) for addr, value in outputs]
    psbt = PartialTransaction.from_io(txins, txouts, locktime=0, BIP69_sort=False)
    for txin_idx, txin in enumerate(txins):
        if txin.address == ADDR_MINE_P2TR:
            txin.witness = construct_witness([psbt.sign_txin(txin_idx, KEY_MINE.get_secret_bytes())])
        else:
            txin.witness = construct_witness([b'foreign'])
    return Transaction(psbt.serialize_to_network())


def with_witness(tx: Transaction, witness: Sequence[bytes]) -> Transaction:
    """Returns tx with another witness: same txid."""
    txins = [TxInput(prevout=txin.prevout, script_sig=txin.script_sig, nsequence=txin.nsequence,
                     witness=construct_witness(witness)) for txin in tx.inputs()]
    return make_tx(txins, [(txout.address, txout.value) for txout in tx.outputs()], locktime=tx.locktime)


def with_outputs(tx: Transaction, outputs: Sequence[Tuple[str, int]]) -> Transaction:
    """The fake-tx attack: the inputs and witnesses of tx, with other outputs."""
    return make_tx(tx.inputs(), outputs, locktime=tx.locktime)


def mined_info(height: int) -> TxMinedInfo:
    return TxMinedInfo(_height=height, timestamp=0, txpos=1, header_hash='00' * 32)


class TestAddressSynchronizerScripts(ElectrumTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.adb = AddressSynchronizer(WalletDB('', storage=None, upgrade=False), self.config)
        self.adb.add_address(ADDR_MINE)
        self.funding_tx = fund(ADDR_MINE, 100_000)
        self.tx = spend(self.funding_tx, [(ADDR_OTHER, 90_000)])
        self.fake_tx = with_outputs(self.tx, [(ADDR_OTHER, 99_000)])

    def _receive(self, tx):
        self.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)

    def _has(self, tx) -> bool:
        return self.adb.db.get_transaction(tx.txid()) is not None

    async def test_invalid_tx_is_rejected(self):
        self._receive(self.funding_tx)
        self._receive(self.tx)
        self._receive(self.fake_tx)
        self.assertFalse(self._has(self.fake_tx))
        # the conflicting tx was not removed
        self.assertTrue(self._has(self.tx))
        # a tx that does not come from the server
        with self.assertRaises(InvalidTxSignature):
            self.adb.add_transaction(self.fake_tx)

    async def test_non_standard_tx_is_rejected(self):
        # valid under consensus rules, but nodes do not relay it: its scriptSig has an opcode that is not a push
        self.adb.add_address(ADDR_MINE_P2PKH)
        funding_tx = fund(ADDR_MINE_P2PKH, 100_000, n=1)
        tx = spend(funding_tx, [(ADDR_OTHER, 90_000)], script_type='p2pkh')
        txin = tx.inputs()[0]
        non_standard_tx = make_tx(
            [TxInput(prevout=txin.prevout, script_sig=txin.script_sig + bytes([opcodes.OP_NOP]), nsequence=txin.nsequence)],
            [(ADDR_OTHER, 90_000)])
        self._receive(funding_tx)
        self._receive(non_standard_tx)
        self.assertFalse(self._has(non_standard_tx))
        self._receive(tx)
        self.assertTrue(self._has(tx))

    async def test_tx_is_rejected_if_interpreter_fails(self):
        self._receive(self.funding_tx)
        bug = IndexError()
        with mock.patch('electrum.address_synchronizer.verify_input', side_effect=bug), \
                mock.patch('electrum.util.send_exception_to_crash_reporter') as crash_reporter:
            self._receive(self.tx)
            self.assertFalse(self._has(self.tx))
            crash_reporter.assert_called_once_with(bug)
            self.assertEqual([f"txid: {self.tx.txid()}"], bug.__notes__)
            # a tx that does not come from the server
            with self.assertRaises(UnverifiableTxSignature):
                self.adb.add_transaction(self.tx)

    async def test_invalid_tx_before_parent(self):
        self._receive(self.fake_tx)
        self.assertTrue(self._has(self.fake_tx))
        self._receive(self.funding_tx)
        self.assertFalse(self._has(self.fake_tx))

    async def test_valid_tx_before_parent(self):
        self._receive(self.tx)
        self._receive(self.funding_tx)
        self.assertTrue(self._has(self.tx))
        self.assertEqual([ADDR_MINE], self.adb.db.get_txi_addresses(self.tx.txid()))

    async def test_linked_inputs_are_verified_once(self):
        self._receive(self.funding_tx)
        with mock.patch('electrum.address_synchronizer.verify_input', wraps=verify_input) as verify:
            self._receive(self.tx)
            self.adb.add_transaction(self.tx, allow_unrelated=True, is_new=False)
        self.assertEqual(1, verify.call_count)

    async def test_inputs_are_verified_once_when_address_is_added(self):
        funding_txs = [fund(ADDR_MINE_2, 100_000, n=1), fund(ADDR_MINE_2, 100_000, n=2)]
        psbt = spending_psbt(funding_txs[0], [(ADDR_OTHER, 190_000)], key=KEY_MINE_2)
        psbt.add_inputs(spending_psbt(funding_txs[1], [], key=KEY_MINE_2).inputs())
        psbt.sign({KEY_MINE_2.get_public_key_bytes(): KEY_MINE_2.get_secret_bytes()})
        tx = Transaction(psbt.serialize())
        for t in (*funding_txs, tx):
            self._receive(t)  # not related to our addresses yet
        self.adb.add_address(ADDR_MINE_2)
        hist = [(t.txid(), TX_HEIGHT_UNCONFIRMED) for t in (*funding_txs, tx)]
        with mock.patch('electrum.address_synchronizer.verify_input', wraps=verify_input) as verify:
            self.adb.receive_history_callback(ADDR_MINE_2, hist, {})
        self.assertEqual(2, len(self.adb.db.get_txi_addr(tx.txid(), ADDR_MINE_2)))
        self.assertEqual(2, verify.call_count)

    async def test_input_with_unknown_parent(self):
        # our input is verified without the output spent by the other input (not taproot)
        foreign_txin = PartialTxInput(prevout=TxOutpoint(txid=bytes(range(32)), out_idx=0), script_sig=b'',
                                      witness=construct_witness([b'foreign']))
        psbt = spending_psbt(self.funding_tx, [(ADDR_OTHER, 150_000)])
        psbt.add_inputs([foreign_txin])
        psbt.sign({KEY_MINE.get_public_key_bytes(): KEY_MINE.get_secret_bytes()})
        tx = Transaction(psbt.serialize())
        self._receive(self.funding_tx)
        fake_tx = with_outputs(tx, [(ADDR_OTHER, 160_000)])
        self._receive(fake_tx)
        self.assertFalse(self._has(fake_tx))
        self._receive(tx)
        self.assertTrue(self._has(tx))

    async def test_taproot_input_with_unknown_parent(self):
        # a taproot signature commits to the outputs spent by all inputs: without them, our input cannot be verified
        self.adb.add_address(ADDR_MINE_P2TR)
        funding_tx = fund(ADDR_MINE_P2TR, 100_000, n=1)
        foreign_funding_tx = fund(ADDR_OTHER, 50_000, n=2)
        tx = spend_taproot([(funding_tx, 0), (foreign_funding_tx, 0)], [(ADDR_OTHER, 140_000)])
        self._receive(funding_tx)
        # a tx that does not come from the server
        with self.assertRaises(UnverifiableTxSignature):
            self.adb.add_transaction(tx)
        self.assertFalse(self.adb.is_held_tx(tx.txid()))
        # received from the server, it is held until the parent is added
        self._receive(tx)
        self.assertFalse(self._has(tx))
        self._receive(foreign_funding_tx)
        self.assertTrue(self._has(tx))

    async def test_taproot_tx_before_parent(self):
        # a taproot signature commits to the outputs spent by all inputs: here, two outputs of the parent being added
        self.adb.add_address(ADDR_MINE_P2TR)
        funding_tx = fund(ADDR_MINE_P2TR, 100_000, 50_000)
        tx = spend_taproot([(funding_tx, 0), (funding_tx, 1)], [(ADDR_OTHER, 140_000)])
        self._receive(tx)
        self._receive(funding_tx)
        self.assertEqual(2, len(self.adb.db.get_txi_addr(tx.txid(), ADDR_MINE_P2TR)))

    async def test_taproot_tx_before_two_parents(self):
        # the first parent alone does not let us verify the tx: it leaves the db with its child, until the second one
        self.adb.add_address(ADDR_MINE_P2TR)
        funding_txs = [fund(ADDR_MINE_P2TR, 100_000, n=1), fund(ADDR_MINE_P2TR, 50_000, n=2)]
        tx = spend_taproot([(funding_tx, 0) for funding_tx in funding_txs], [(ADDR_MINE, 140_000)])
        child_tx = spend(tx, [(ADDR_OTHER, 130_000)])
        for t in (tx, child_tx, funding_txs[0]):
            self._receive(t)
        self.assertFalse(self._has(tx))
        self.assertFalse(self._has(child_tx))
        self._receive(funding_txs[1])
        self.assertEqual(2, len(self.adb.db.get_txi_addr(tx.txid(), ADDR_MINE_P2TR)))
        self.assertEqual([ADDR_MINE], self.adb.db.get_txi_addresses(child_tx.txid()))
        for t in (tx, child_tx):
            self.assertEqual(TX_HEIGHT_UNCONFIRMED, self.adb.get_tx_height(t.txid()).height())

    async def test_input_spending_missing_output_of_stored_tx(self):
        # funding_tx has a single output: the input is handled as if its parent was unknown
        txin = TxInput(prevout=TxOutpoint(txid=bytes.fromhex(self.funding_tx.txid()), out_idx=1), script_sig=b'',
                       witness=construct_witness([b'x']))
        tx = make_tx([txin], [(ADDR_OTHER, 90_000)])
        self._receive(self.funding_tx)
        self._receive(tx)
        self.assertTrue(self._has(tx))
        self.assertIsNone(self.adb.get_txin_address(tx.inputs()[0]))
        self.assertIsNone(self.adb.get_txin_value(tx.inputs()[0]))

    async def test_add_parent_with_stale_spent_outpoint(self):
        missing_txid = 'ab' * 32
        self.adb.db.set_spent_outpoint(self.funding_tx.txid(), 0, missing_txid)
        self.adb.db.add_txi_addr(missing_txid, ADDR_MINE, self.funding_tx.txid() + ':0', 100_000)
        self._receive(self.funding_tx)

    async def test_invalid_copy_of_stored_tx(self):
        self._receive(self.funding_tx)
        self._receive(self.tx)
        bad_copy = with_witness(self.tx, [b'bad'])
        self.assertEqual(self.tx.txid(), bad_copy.txid())
        self._receive(bad_copy)
        self.assertEqual(self.tx.wtxid(), self.adb.db.get_transaction(self.tx.txid()).wtxid())

    async def test_invalid_copy_of_stored_unlinked_tx(self):
        funding_tx = fund(ADDR_MINE_2, 100_000, n=1)
        tx = spend(funding_tx, [(ADDR_OTHER, 90_000)], key=KEY_MINE_2)
        for t in (funding_tx, tx):
            self._receive(t)  # not related to our addresses yet
        self.adb.add_address(ADDR_MINE_2)
        self._receive(with_witness(tx, [b'bad']))
        self.assertEqual(tx.wtxid(), self.adb.db.get_transaction(tx.txid()).wtxid())

    async def test_signed_copy_of_stored_unsigned_tx(self):
        self._receive(self.funding_tx)
        unsigned_tx = spending_psbt(self.funding_tx, [(ADDR_OTHER, 90_000)])
        bad_copy = with_witness(self.tx, [b'bad'])
        self.assertFalse(unsigned_tx.is_complete())
        self.assertEqual(unsigned_tx.txid(), bad_copy.txid())
        self.assertEqual(unsigned_tx.txid(), self.tx.txid())
        self.adb.add_transaction(unsigned_tx)
        self._receive(bad_copy)
        self.assertFalse(self.adb.db.get_transaction(unsigned_tx.txid()).is_complete())
        self._receive(self.tx)
        self.assertEqual(self.tx.wtxid(), self.adb.db.get_transaction(unsigned_tx.txid()).wtxid())

    async def test_history_update_with_invalid_tx(self):
        funding_tx = fund(ADDR_MINE_2, 100_000, n=1)
        tx = with_witness(spend(funding_tx, [(ADDR_OTHER, 90_000)], key=KEY_MINE_2), [b'bad'])
        other_funding_tx = fund(ADDR_MINE_2, 50_000, n=2)
        for t in (funding_tx, tx, other_funding_tx):
            self._receive(t)  # not related to our addresses yet
        self.adb.add_address(ADDR_MINE_2)
        hist = [(t.txid(), TX_HEIGHT_UNCONFIRMED) for t in (tx, funding_tx, other_funding_tx)]
        self.adb.receive_history_callback(ADDR_MINE_2, hist, {})
        self.assertFalse(self._has(tx))
        self.assertEqual([ADDR_MINE_2], self.adb.db.get_txo_addresses(funding_tx.txid()))
        self.assertEqual([ADDR_MINE_2], self.adb.db.get_txo_addresses(other_funding_tx.txid()))

    async def test_history_update_with_stored_tx_missing_a_parent(self):
        funding_txs = [fund(ADDR_MINE_P2TR, 100_000, n=1), fund(ADDR_MINE_P2TR, 50_000, n=2)]
        tx = spend_taproot([(funding_tx, 0) for funding_tx in funding_txs], [(ADDR_OTHER, 140_000)])
        for t in (funding_txs[0], tx):
            self._receive(t)  # not related to our addresses yet
        self.adb.add_address(ADDR_MINE_P2TR)
        hist = [(t.txid(), TX_HEIGHT_UNCONFIRMED) for t in (tx, funding_txs[0])]
        self.adb.receive_history_callback(ADDR_MINE_P2TR, hist, {})
        self.assertFalse(self._has(tx))
        self.assertTrue(self.adb.is_held_tx(tx.txid()))
        # a parent that does not come from the server
        self.adb.add_transaction(funding_txs[1])
        self.assertEqual(2, len(self.adb.db.get_txi_addr(tx.txid(), ADDR_MINE_P2TR)))

    async def test_verified_tx_is_not_checked(self):
        self._receive(self.funding_tx)
        self.adb.add_verified_tx(self.fake_tx.txid(), mined_info(100))
        self.adb.receive_tx_callback(self.fake_tx, tx_height=100)
        self.assertTrue(self._has(self.fake_tx))

    async def test_tx_claimed_mined_is_added_once_verified(self):
        self._receive(self.funding_tx)
        self._receive(self.fake_tx)  # rejected while unconfirmed
        self.adb.add_unverified_or_unconfirmed_tx(self.fake_tx.txid(), 100)
        self.adb.receive_tx_callback(self.fake_tx)
        self.assertFalse(self._has(self.fake_tx))
        self.adb.add_verified_tx(self.fake_tx.txid(), mined_info(100))
        self.assertTrue(self._has(self.fake_tx))

    async def test_tx_claimed_mined_is_checked_if_not_at_height(self):
        self._receive(self.funding_tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.fake_tx.txid(), 100)
        self.adb.receive_tx_callback(self.fake_tx)
        self.adb.remove_unverified_tx(self.fake_tx.txid(), 100)
        self.assertFalse(self._has(self.fake_tx))

    async def test_tx_claimed_mined_then_unconfirmed_is_checked(self):
        self._receive(self.funding_tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.fake_tx.txid(), 100)
        self.adb.receive_tx_callback(self.fake_tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.fake_tx.txid(), TX_HEIGHT_UNCONFIRMED)
        self.adb.receive_tx_callback(self.fake_tx)
        self.adb.add_verified_tx(self.fake_tx.txid(), mined_info(100))
        self.assertFalse(self._has(self.fake_tx))

    def _make_synchronizer(self) -> Synchronizer:
        sync = Synchronizer.__new__(Synchronizer)
        sync.adb = self.adb
        Synchronizer._reset(sync)
        return sync

    def _orphan_tx(self, *, n: int = 1, value: int = 140_000) -> Tuple[Transaction, Transaction]:
        """Returns a tx that spends one of our taproot coins, and a coin of a parent that we do not have: it
        is held when the server sends it. Returns that parent too."""
        self.adb.add_address(ADDR_MINE_P2TR)
        funding_tx, missing_parent = fund(ADDR_MINE_P2TR, 100_000, n=n), fund(ADDR_OTHER, 50_000, n=n + 1)
        self._receive(funding_tx)
        return spend_taproot([(funding_tx, 0), (missing_parent, 0)], [(ADDR_OTHER, value)]), missing_parent

    async def test_orphan_txs_are_added_in_the_order_received(self):
        # the tx received last replaces the other one
        tx, missing_parent = self._orphan_tx()
        replacement_tx, _ = self._orphan_tx(value=130_000)
        for t in (tx, replacement_tx, missing_parent):
            self._receive(t)
        self.assertFalse(self._has(tx))
        self.assertTrue(self._has(replacement_tx))

    async def test_orphan_tx_is_verified_once_all_parents_are_added(self):
        self.adb.add_address(ADDR_MINE_P2TR)
        funding_txs = [fund(ADDR_MINE_P2TR, 100_000, n=n) for n in (1, 2, 3)]
        tx = spend_taproot([(funding_tx, 0) for funding_tx in funding_txs], [(ADDR_OTHER, 290_000)])
        self._receive(funding_txs[0])
        self._receive(tx)
        with mock.patch('electrum.address_synchronizer.verify_input', wraps=verify_input) as verify:
            self._receive(funding_txs[1])
            self.assertEqual(0, verify.call_count)
            self._receive(funding_txs[2])
        self.assertEqual(3, verify.call_count)

    async def test_oldest_orphan_tx_is_dropped_if_too_many(self):
        (tx, missing_parent), (tx2, _) = [self._orphan_tx(n=n) for n in (1, 3)]
        with mock.patch('electrum.address_synchronizer.MAX_HELD_ORPHAN_TXS', 1):
            for t in (tx, tx2, missing_parent):
                self._receive(t)
        self.assertFalse(self._has(tx))
        self.assertTrue(self.adb.is_held_tx(tx2.txid()))

    async def test_orphan_tx_no_longer_listed_is_dropped(self):
        # the server may have replaced it: it would replace the new tx when its parent is added
        tx, missing_parent = self._orphan_tx()
        hist = [(tx.inputs()[0].prevout.txid.hex(), TX_HEIGHT_UNCONFIRMED), (tx.txid(), TX_HEIGHT_UNCONFIRMED),
                (self.tx.txid(), 100)]
        self.adb.receive_history_callback(ADDR_MINE_P2TR, hist, {})
        self._receive(tx)
        self.adb.receive_tx_callback(self.tx)
        self.adb.receive_history_callback(ADDR_MINE_P2TR, hist, {})
        self.assertTrue(self.adb.is_held_tx(tx.txid()))
        self.adb.receive_history_callback(ADDR_MINE_P2TR, hist[:1], {})
        self.assertFalse(self.adb.is_held_tx(tx.txid()))
        self._receive(missing_parent)
        self.assertFalse(self._has(tx))
        # a tx held until verified is kept: the verifier finds out if it is not at the height claimed
        self.assertTrue(self.adb.is_held_tx(self.tx.txid()))

    async def test_orphan_tx_claimed_mined_is_added_once_verified(self):
        sync = self._make_synchronizer()
        tx, missing_parent = self._orphan_tx()
        fake_tx = with_outputs(tx, [(ADDR_OTHER, 149_000)])
        self._receive(fake_tx)
        self.adb.add_unverified_or_unconfirmed_tx(fake_tx.txid(), 100)
        await sync._request_missing_txs([(fake_tx.txid(), 100)])
        self.assertEqual(set(), sync.requested_tx)
        # its scripts are not verified when the parent is added
        self._receive(missing_parent)
        self.assertFalse(self._has(fake_tx))
        self.adb.add_verified_tx(fake_tx.txid(), mined_info(100))
        self.assertTrue(self._has(fake_tx))

    async def test_held_tx_is_not_requested_again(self):
        self.adb.add_unverified_or_unconfirmed_tx(self.tx.txid(), 100)
        sync = self._make_synchronizer()
        self.adb.receive_tx_callback(self.tx)
        await sync._request_missing_txs([(self.tx.txid(), 100)])
        self.assertEqual(set(), sync.requested_tx)

    async def test_held_tx_is_requested_again_if_unconfirmed(self):
        self.adb.add_unverified_or_unconfirmed_tx(self.tx.txid(), 100)
        sync = self._make_synchronizer()
        sync._get_transaction = mock.AsyncMock()
        self.adb.receive_tx_callback(self.tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.tx.txid(), TX_HEIGHT_UNCONFIRMED)
        await sync._request_missing_txs([(self.tx.txid(), TX_HEIGHT_UNCONFIRMED)])
        sync._get_transaction.assert_called_once_with(self.tx.txid(), allow_server_not_finding_tx=False)

    async def test_held_txs_are_dropped_on_server_switch(self):
        self._receive(self.funding_tx)
        self.adb.add_unverified_or_unconfirmed_tx(self.tx.txid(), 100)
        sync = self._make_synchronizer()
        self.adb.receive_tx_callback(self.tx)
        orphan_tx, missing_parent = self._orphan_tx()
        self._receive(orphan_tx)
        Synchronizer._reset(sync)
        self.assertFalse(self.adb.is_held_tx(self.tx.txid()))
        self.adb.add_verified_tx(self.tx.txid(), mined_info(100))
        self.assertFalse(self._has(self.tx))
        self.assertFalse(self.adb.is_held_tx(orphan_tx.txid()))
        self._receive(missing_parent)
        self.assertFalse(self._has(orphan_tx))

