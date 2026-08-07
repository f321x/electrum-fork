# Review finding: "preimage is public" is treated as reversible

Branch: `swap_improvement_1` (analysed at commit `9852eb17d`, working tree had unrelated
prepayment-sanity-check changes). Status: **investigated, nothing changed. No fix applied.**

---

## 1. The bug, concisely

For a reverse swap `swap.preimage` is always set (we generated it), so it cannot answer
"have we already leaked it?". The code answers that question with
`_get_public_preimage()` (`electrum/submarine_swaps.py:512`), which reads the *current*
spender of the funding UTXO out of the adb and looks for the preimage in its witness.
That is a live query, not a latch:

- `submarine_swaps.py:582` overwrites `swap.spending_txid` with whatever spends the UTXO
  right now — including the counterparty's tx.
- After locktime the server can RBF our claim tx away with its refund tx. That witness
  carries no preimage, so `_get_public_preimage()` flips back to `None`.
- The gate at `submarine_swaps.py:621` then reads
  `remaining_time <= MIN_LOCKTIME_DELTA_FOR_CLAIM and public_preimage is None` → `return`,
  permanently. We stop re-queuing the claim at exactly the moment the preimage *is* in the
  server's hands, so the server settles the LN HTLC **and** keeps its coins.
- The claim branch has no timelock (`create_claim_txin`, `submarine_swaps.py:1596-1601`,
  witness `[sig, preimage, script]` — our signature is required, so the server cannot use
  the leaked preimage itself). It stays spendable forever. So this is a fee race we
  forfeit, not a right we lose. The docstring's "it is already too late to claim then" is
  wrong.
- `submarine_swaps.py:645` sets `expiry = swap.locktime - MIN_LOCKTIME_DELTA_FOR_CLAIM` on
  the re-queued `SweepInfo` for the same reason.
- `submarine_swaps.py:588-597` then marks the stolen swap `is_redeemed` and drops the
  lnwatcher callback once the theft has `SPENDER_FINALITY_DELAY` (6) confirmations.

Contradicts the invariant asserted by
`tests/test_submarine_swaps.py:658` `test_reverse_swap_keeps_claiming_after_the_preimage_became_public`.

The proper latch already exists and is used **for the forward direction only**
(`submarine_swaps.py:610`): `lnworker.save_preimage(..., mark_as_public=True)` /
`lnworker.is_preimage_public()`, `electrum/lnworker.py:2826-2874`, where line 2839
explicitly forbids a True→False transition.

Why the forward direction is safe: there, `swap.preimage is None` until we see it, and it
is persisted (`submarine_swaps.py:599-611`), so `swap.preimage` itself acts as the latch.
Reverse has no such field available.

---

## 2. Corrections to the original finding

1. **`add_sweep_input` is not one of the three places.** `txbatcher.py:305-308` refuses
   only *confirmed* spenders, which is correct behaviour. What actually blocks re-entry
   there is `_unconfirmed_sweeps` (`txbatcher.py:299`, added at `:309`, cleared only when a
   batch tx confirms, `:577-582`), plus `_start_new_batch` dropping every base-tx input via
   `_to_sweep_after` (`:334-337`, called at `:588`) when a replacement broadcast fails
   (`:455-470`).
2. **The suggested "cheap independent fix" is wrong as stated.** Requiring
   `extract_preimage(...) is not None` before declaring `is_redeemed` would, for a reverse
   swap whose refund reached 6 confirmations, keep a dead swap in the watch list forever —
   the money genuinely is gone at that point. `is_redeemed` means "terminal, stop watching"
   (see `submarine_swaps.py:305`, `:1754`), not "we got paid". The real issue there is
   *labelling* (we report a swap we lost as redeemed), not security.
3. **"Not a net regression vs master" holds.** Master has no `MIN_LOCKTIME_DELTA_FOR_CLAIM`
   gate for reverse-with-preimage, so it keeps calling `add_sweep_input` — but that is a
   no-op because of `_unconfirmed_sweeps`, and the batcher blocks at
   `txbatcher.py:367-370` all the same. Master also sets `is_redeemed` on any final spender
   (`REDEEM_AFTER_DOUBLE_SPENT_DELAY`). Same dead end. The new gate makes the concession
   explicit and restart-persistent rather than incidental.

---

## 3. Exploitability — Medium, upper end

The server cannot *force* the stall, but it controls the timing that makes it cheap to farm:

- It picks the locktime (client only checks `> MIN_LOCKTIME_DELTA = 60`,
  `submarine_swaps.py:1286`) and it controls when the funding tx confirms. We refuse to
  claim inside 30 blocks of locktime (`:621`; tests `test_submarine_swaps.py:615` and
  `:636`), so the server's optimum is funding confirming at ~`locktime - 31`: we leak the
  preimage and only a ~31-block stall is needed.
- Our claim is bumped only toward `FEE_POLICY_SWAPS` (default `eta:2`,
  `simple_config.py:787`) via `_should_bump_fee` (`txbatcher.py:374-384`), which lags during
  fee spikes.
- Free option for the server: broadcast the refund at locktime on *every* swap. If our
  claim already confirmed the refund is simply invalid and costs nothing; if it stalled, one
  RBF converts a race we might win into an automatic total loss. Offering swaps during a
  mempool spike raises the hit rate.
- **Amplifier the finding missed:** the `claim_to_output` flow (`submarine_swaps.py:665-701`,
  "submarine payments") broadcasts a **fixed-fee, never-bumped** tx by design. That is the
  flow most likely to stall 30+ blocks, and its docstring calls the no-bumping an
  "acceptable low-risk tradeoff" — which is only true if a stalled claim stays alive.
- Non-malicious triggering is plausible too: an honest server refunding routinely at expiry,
  after settling the LN HTLC it saw the preimage in, produces the same loss.

Constants for reference (`submarine_swaps.py:77-97`):
`MIN_LOCKTIME_DELTA_FOR_CLAIM = 30`, `MIN_LOCKTIME_DELTA = 60`, `MAX_LOCKTIME_DELTA = 100`,
`SPENDER_FINALITY_DELAY = 6`.

---

## 4. Proposed fix

### 4.1 Make the latch real — necessary, ~4 lines

`submarine_swaps.py:512` `_get_public_preimage`:

```python
if swap.spending_txid is not None:
    # note: keep the existing comment about a malicious Electrum server omitting the claim tx
    spending_tx = self.lnwatcher.adb.get_transaction(swap.spending_txid)
    if spending_tx is not None and (preimage := self.extract_preimage(swap, spending_tx)):
        # latch: a preimage that was public once cannot become secret again, even if the
        # counterparty replaces this tx with one that does not reveal it
        self.lnworker.save_preimage(swap.payment_hash, preimage, mark_as_public=True)
        return preimage
if self.lnworker.is_preimage_public(swap.payment_hash):
    return self.lnworker.get_preimage(swap.payment_hash)
return None
```

Fixes `:597`, `:621` and `:645` at once and survives restarts. Also gets a second signal for
free: `lnchannel.receive_htlc_settle` (`electrum/lnchannel.py:1748`) already marks the
preimage public when the server settles our outgoing HTLC — i.e. the instant the server
monetises the theft, our latch flips and we resume claiming.

**Latch only on *observed* publication.** Latching at `add_sweep_input` time (queue time)
would break the "don't reveal near locktime" invariant that
`test_submarine_swaps.py:615`/`:636` protect: a sweep can be queued and then dropped by the
batcher without ever being broadcast. Residual race: broadcast → replaced before
`_claim_swap` observes it. Small (we see our own tx via our own adb) and no worse than
today. Airtight alternative: latch from the txbatcher after a successful broadcast, via a
callback on `SweepInfo` — more invasive.

### 4.2 Let the batcher stay in the race

Add a flag to `SweepInfo` (`electrum/lnsweep.py`), e.g. `outbid_foreign_spender`, set from
`swap.is_reverse and public_preimage is not None` at `submarine_swaps.py:647`, and honour it
in `txbatcher.py:367-370` — skip only on a *confirmed* foreign spender:

```python
if tx_mined_status.height() not in [TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE]:
    if not (sweep_info.outbid_foreign_spender
            and tx_mined_status.height() <= TX_HEIGHT_UNCONFIRMED):
        continue
```

and let `add_sweep_input` refresh an existing entry instead of early-returning on
`_unconfirmed_sweeps` (`txbatcher.py:299`), so the re-queued `expiry=None` version actually
lands.

Caveats:
- This only keeps us bidding at the *estimated market* rate; it does not outbid a server
  willing to overpay. Bidding up to the swap value when the preimage is public is a separate,
  larger decision.
- Watch for a broadcast-fail spin loop: build replacement → `try_broadcasting` fails (RBF fee
  rules) → `_start_new_batch` → repeat every `SLEEP_INTERVAL`.
- For `claim_to_output` swaps this has little effect: the tx cannot be re-fee'd without
  changing the payee amount. That is an inherent design tradeoff, not this bug.

### 4.3 Report the loss honestly

Keep the terminal transition at `submarine_swaps.py:588-597` (funds really are gone at 6
confs) but distinguish "spender carried our preimage" from "counterparty refunded", so a
lost swap is not surfaced as redeemed. Cosmetic relative to 4.1/4.2.

### 4.4 Regression test

Mirror `test_reverse_swap_keeps_claiming_after_the_preimage_became_public`
(`tests/test_submarine_swaps.py:658`), but instead of only stalling, have the server
broadcast `server_refund_tx` replacing our claim past locktime; then assert `_claim_swap`
still queues the claim and the batcher still attempts a replacement.

Note while there: the existing test only passes because of its `restart_txbatcher()` call
(`tests/test_submarine_swaps.py:151`), which clears `_unconfirmed_sweeps`. Worth making that
dependency explicit.

---

## 5. Confidence

Mechanism verified by reading the code paths, **not** by executing the scenario. Section 4.2
in particular (exact minimal txbatcher change) should be confirmed with the test in 4.4 —
the batcher's behaviour after a foreign replacement depends on whether the batch's
`_prevout` (`txbatcher.py:596`, first input of the base tx) happens to be the lockup
outpoint, which changes which of `find_base_tx:401-407`, `_to_sweep_after:367-370` and
`_start_new_batch:588` actually drops us out.
