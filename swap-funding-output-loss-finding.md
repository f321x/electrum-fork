# Review finding: `_to_pay_after` returns the live list → `NotEnoughFunds` permanently deletes a swap funding output

Status: **confirmed real**, not yet fixed. Analysis done 2026-08-07 on branch `swap_improvement_1`
(HEAD `9852eb17d`, with the uncommitted `submarine_swaps.py` prepay-sanity-check diff in the tree).

Nothing was modified — this is analysis only.

---

## 1. The bug

`_to_pay_after` is asymmetric (`electrum/txbatcher.py:314-326`):

```python
if not tx:
    return self.batch_payments      # the live list
...
to_pay = []                         # fresh list when tx is not None
```

`create_next_transaction` treats the return value as scratch space (`electrum/txbatcher.py:510-515`):

```python
except NotEnoughFunds:
    if to_pay:
        k = max(to_pay, key=lambda x: x.value)
        self.logger.info(f'Not enough funds, removing output {k}')
        to_pay.remove(k)            # deletes from self.batch_payments when base_tx is None
        continue
```

So when `base_tx is None`, "we cannot afford this right now" silently becomes "this payment never
happens". When `base_tx` is not None the removal operates on a copy and is harmless — that asymmetry
is the tell.

`base_tx` is `None` in two ordinary states:

- a fresh batch (`storage['prevout'] = None`, `txbatcher.py:128`), and
- after `_start_new_batch` clears `_prevout` (`txbatcher.py:592`), which runs when the previous
  batch tx confirms (`:413`), when broadcast fails (`:470`), or when the base tx has no change (`:603`).

`find_base_tx` returns `None` whenever `self._prevout` is falsy (`txbatcher.py:390-392`).

## 2. Why the loss is permanent

The only producer of payment outputs is the swap server: `submarine_swaps.py:762`
(`hold_invoice_callback`). No other caller of `txbatcher.add_payment_output` exists.

```python
# submarine_swaps.py:754-762
with self.swaps_lock:
    if swap._is_cancelled: raise OnionRoutingFailure(...)
    if swap.is_funded(): return
    swap._payment_pending = True        # latched BEFORE queueing
output = self.create_funding_output(swap)
self.wallet.txbatcher.add_payment_output('swaps', output)
```

- `_payment_pending = True` is latched unconditionally, so `SwapData.is_funded()`
  (`submarine_swaps.py:232-233`) stays true forever. That blocks `cancel_normal_swap`
  (`:477-479`) and the db/`_swaps` cleanup inside `_fail_swap` (`:492-510`).
- The hold-invoice callback fires **exactly once**, enforced by setting the mpp set to
  `RecvMPPResolution.SETTLING` (`lnpeer.py:3206-3208`).
- A SETTLING set with no preimage is never auto-failed and never re-dispatched
  (`lnpeer.py:3255-3268` — it just returns `preimage=None` forever).
- `received_mpp_htlcs` is **db-backed** (`lnworker.py:1062`), so SETTLING survives a restart.
  A server restart does *not* recover the dropped payment. (`_payment_pending` is a plain class
  attribute, not an `attr.ib`, so it *does* reset on restart — but that doesn't help, because the
  callback is never invoked again.)

`batch_payments` is not persisted either (see the module header comment, `txbatcher.py:55-58`), but
that is not what makes this permanent — the persisted SETTLING resolution is.

## 3. Impact per occurrence

Client:
- the prepayment (`2 * mining_fee`, `submarine_swaps.py:813`) has already settled → **lost**;
- the main HTLC hangs until `swap.locktime` (`LOCKTIME_DELTA_REFUND = 70` blocks, ~12 h), when
  `_claim_swap` (`:564-569`) → `_fail_swap` → `unregister_hold_invoice` → `set_mpp_resolution(FAILED)`
  (`lnworker.py:2918-2924`) fails it;
- **principal is not lost**, and there is no force-close: `add_normal_swap:835` already asserts the
  invoice CLTV exceeds `locktime + MIN_LOCKTIME_DELTA + SPENDER_FINALITY_DELAY`.

Server:
- a zombie swap entry stuck as "funded" in the db until `remaining_time <= -2016`
  (`submarine_swaps.py:565-568`), i.e. ~2 weeks past locktime.

## 4. Reachability — realistic, and easier to trigger than the report claims

`server_create_swap` → `create_normal_swap` → `_get_recv_amount(..., is_reverse=True)` →
`check_invoice_amount` does bound each request by `_max_forward`. But (`submarine_swaps.py:1346-1354`):

```python
oc_balance_sat: int = self.wallet.get_spendable_balance_sat()
max_forward = min(int(self.lnworker.num_sats_can_receive()), oc_balance_sat, MAX_SWAP_AMT)
self._max_forward = self._keep_leading_digits(max_forward, 2)
```

- the **entire** spendable balance is advertised;
- **nothing is reserved** for swaps already created or already committed;
- recomputed only every `LIQUIDITY_UPDATE_INTERVAL_SEC = 30` (`submarine_swaps.py:1848`).

The 30 s figure is a red herring: `_max_forward` only shrinks once the balance moves, and the
balance only moves once a swap is *funded*. So an attacker can create N max-size swaps at leisure
and pay them all together — every one passes the amount check. Two are enough.

Aggravating factors:
- `_keep_leading_digits(x, 2)` can leave ~0 headroom on round balances (e.g. exactly 1_000_000).
- `get_spendable_balance_sat()` counts local coins, while `_create_batch_tx` uses
  `get_spendable_coins(nonlocal_only=True)` (`txbatcher.py:562`) — the advertised balance can exceed
  what the batcher will actually spend.

Also fires without any attacker: two honest clients hitting a modestly funded server concurrently.
An attacker can additionally grief honest clients by keeping the server's on-chain balance exhausted.

No test covers the `NotEnoughFunds` branch (`tests/test_txbatcher.py`).

## 5. Why the proposed one-line fix is NOT enough

`return list(self.batch_payments)` alone is unsafe. There is no API to un-queue a payment output.
Make the drop non-destructive and the output stays queued indefinitely — so the batcher can broadcast
the funding tx **after** `_fail_swap` already failed the client's HTLCs at locktime.

For a server-side normal swap the **client** holds the preimage (the server receives
`request['preimageHash']`, `submarine_swaps.py:1607`). Late funding therefore lets the client sweep
on-chain funds it never paid for — racing the server's post-locktime refund at best, losing the full
`onchain_amount` at worst.

**Retryable must be paired with expirable.**

## 6. Proposed fix, in order

1. **Reject instead of silently dropping.** Act on the existing TODO at `txbatcher.py:270`: have
   `add_payment_output` check fundability and raise `NotEnoughFunds`. In `hold_invoice_callback`,
   catch it, un-latch `_payment_pending`, and raise
   `OnionRoutingFailure(TEMPORARY_NODE_FAILURE)` — `lnpeer.py:3203-3205` already converts that to
   `RecvMPPResolution.FAILED`, so the client's HTLCs fail immediately. Worst case becomes a normal
   failed swap instead of 12 h of stuck liquidity.

2. **Stop the aliasing** — `return list(self.batch_payments)` at `txbatcher.py:316`. Keep it as
   defence in depth: the pre-check in (1) can still race against concurrent sweeps and fee
   re-estimation within the same batch.

3. **Give queued payments an expiry** so (2) cannot cause late funding. Cleanest shape mirrors
   `SweepInfo.is_expired`: an optional expiry height on the payment output (set to `swap.locktime`),
   dropped deliberately by the batcher, with the swap manager able to observe the drop and clear
   `_payment_pending`.

4. **Prevent it at the source**: subtract committed-but-unfunded swap amounts (plus a fee buffer)
   from `_max_forward` in `server_update_pairs`. Reserve at swap **creation**, not at funding —
   reserving only what is already in `batch_payments` does not stop create-two-then-pay-both.
   Release the reservation on invoice expiry (`exp_delay=300`, `submarine_swaps.py:825`) rather than
   at locktime, so unpaid swaps cannot grief advertised liquidity for 70 blocks.

5. **Test** the `NotEnoughFunds` branch: assert `batch_payments` is intact after a failed funding
   attempt, and that the payment is funded once the balance recovers.

(4) is the only change that avoids client loss entirely; (1)+(2) are the minimal correctness fix;
(3) is required if you want (2)'s retry semantics.

## 7. Code references

| What | Where |
| --- | --- |
| aliasing return | `electrum/txbatcher.py:314-316` |
| destructive drop | `electrum/txbatcher.py:510-515` |
| `_prevout` cleared → `base_tx is None` | `electrum/txbatcher.py:390-392`, `:585-592` |
| TODO "maybe we should raise NotEnoughFunds" | `electrum/txbatcher.py:268-271` |
| batcher coin selection (`nonlocal_only=True`) | `electrum/txbatcher.py:562` |
| `_payment_pending` latch | `electrum/submarine_swaps.py:754-762` |
| `is_funded()` | `electrum/submarine_swaps.py:232-233` |
| `_fail_swap` cleanup guarded by `is_funded()` | `electrum/submarine_swaps.py:484-510` |
| expiry / `-2016` reset | `electrum/submarine_swaps.py:559-572` |
| `server_update_pairs` (no reservation) | `electrum/submarine_swaps.py:1346-1361` |
| `check_invoice_amount` / `_get_recv_amount` | `electrum/submarine_swaps.py:1401-1436` |
| `server_create_swap` (reversesubmarine) | `electrum/submarine_swaps.py:1599-1624` |
| `LIQUIDITY_UPDATE_INTERVAL_SEC = 30` | `electrum/submarine_swaps.py:1848` |
| callback-once via SETTLING | `electrum/lnpeer.py:3184-3213` |
| SETTLING never auto-fails | `electrum/lnpeer.py:3255-3268` |
| `received_mpp_htlcs` persisted | `electrum/lnworker.py:1062` |
| `unregister_hold_invoice` fails the set | `electrum/lnworker.py:2918-2924` |
