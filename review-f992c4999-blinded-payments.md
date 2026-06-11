# Code Review — `f992c4999` "lnonion: support payment path blinding"

- **Commit:** `f992c499997efa4c7abce75cfff619c27672075d`
- **Author:** Sander van Grieken `<sander@outrightsolutions.nl>` (Co-Authored-By: f321x)
- **Date:** 2025-11-11
- **Branch:** `bolt12_path_blinding` (commit is deep in branch history; **key findings verified to still exist at branch HEAD**)
- **Spec reference:** `bolts-lightning-specification/04-onion-routing.md`

## Scope & caveat

The commit prepares Electrum's Lightning code to **handle incoming blinded (BOLT-12 / route-blinding) payments**. Nothing here is currently exploitable for fund loss because:

- Incoming blinded **receive** is deliberately stubbed: `_check_accepted_final_htlc` raises `"we cannot receive blinded payments yet."`
- Blinded **forwarding** runs only when `EXPERIMENTAL_LN_FORWARD_PAYMENTS` is enabled and Electrum is an intermediate hop in someone else's blinded path.

So treat severities as *"correctness within the new code path"* — i.e. the things to fix before enabling blinded receive/forward.

**Overall:** Well-structured commit; the core route-blinding cryptography is correct (intro-point vs non-intro key handling, the two shared-secret derivations, and the `E_{i+1}` chain all verified against BOLT-04). All issues are in peripheral logic — fee math, spec MUST-checks, caching, and error codes.

---

## 🔴 High

### [ ] H1 — Wrong forwarding-fee formula
**File:** `electrum/lnworker.py`, `_maybe_forward_htlc` (blinded branch)

```python
next_amount_msat_htlc = htlc.amount_msat
next_amount_msat_htlc -= int(next_amount_msat_htlc * payment_relay.get('fee_proportional_millionths') / 1_000_000)
next_amount_msat_htlc -= payment_relay.get('fee_base_msat')
```

Computes `amt − floor(amt·prop/1e6) − base`, which is **not** the spec formula. BOLT-04 (`04-onion-routing.md:340`) mandates the inverse-rounded form:

```
amt_to_forward = ((amount_msat − fee_base_msat)·1e6 + 1e6 + fee_proportional_millionths − 1) / (1e6 + fee_proportional_millionths)
```

**Concrete failure** (amount=1_000_000, base=1000, prop=1000): Electrum forwards **998_000**, spec says **998_002** — it forwards *too little*, and the shortfall **compounds per hop**. The sender sizes the route with the spec formula, so the final recipient receives less than `amt_to_forward` and rejects the whole payment (`INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS`). Blinded payments routed *through* an Electrum hop cannot complete.

Two secondary problems on the same lines:
- **Float division** (`/ 1_000_000`) loses integer precision once `amt·prop` exceeds 2⁵³ (~a 1 BTC HTLC with prop≈1e6), making the result non-deterministic vs other nodes.
- **No underflow / insufficient-fee guard**: if `amount_msat < fee_base_msat`, `next_amount` goes negative (caught later as a misleading `TEMPORARY_CHANNEL_FAILURE` rather than a payload error).

**Proposed fix** — integer math matching the spec, plus a guard:
```python
prop = payment_relay['fee_proportional_millionths']
base = payment_relay['fee_base_msat']
next_amount_msat_htlc = ((htlc.amount_msat - base) * 1_000_000 + 1_000_000 + prop - 1) // (1_000_000 + prop)
next_cltv_abs = htlc.cltv_abs - payment_relay['cltv_expiry_delta']
if next_amount_msat_htlc <= 0 or htlc.amount_msat - next_amount_msat_htlc < base:
    raise OnionRoutingFailure(code=OnionFailureCode.INVALID_ONION_BLINDING, data=onion_hash)
```

---

## 🟠 Medium

### [ ] M1 — Onion cache key omits `path_key`
**File:** `electrum/lnpeer.py:3300`, `_process_incoming_onion_packet`

```python
cache_key = sha256(onion_hash + payment_hash + bytes([is_trampoline]))   # path_key not included
```

`path_key` materially changes processing (re-blinds the private key, drives `blinded_path_recipient_data` / `next_path_key`), and for non-intro hops it arrives on the **wire** (`update_add_htlc_tlvs`), independently of the onion. Two HTLCs with the same onion+payment_hash but different wire `path_key` collide; the first cached `ProcessedOnionPacket` is returned for the second, so forwarding can run with the wrong scid/fees/next-path-key. Latent today (receive stubbed) but the forwarding path already consumes these cached fields.

**Proposed fix:**
```python
cache_key = sha256(onion_hash + payment_hash + bytes([is_trampoline]) + (path_key or b''))
```

### [ ] M2 — `next_path_key_override` (encrypted_data TLV type 8) ignored
**File:** `electrum/lnonion.py`, `process_onion_packet`

```python
if path_key:
    next_path_key = next_blinding_from_shared_secret(path_key, recipient_data_shared_secret)
```

BOLT-04:651 says the forwarder **MUST** use `next_path_key_override` as the next path key when present. The onion-*message* path (`onion_message.py`) already honors it; the payment path doesn't, so any blinded *payment* route using an override silently breaks at the next hop. (Real-world payment likelihood is low — the spec discourages overrides for payments — but it's a hard MUST.)

**Proposed fix:**
```python
if path_key:
    override = (blinded_path_recipient_data or {}).get('next_path_key_override', {}).get('path_key')
    next_path_key = override or next_blinding_from_shared_secret(path_key, recipient_data_shared_secret)
```

### [ ] M3 — Missing forwarder MUST-checks (`payment_constraints`, `allowed_features`)
**File:** `electrum/lnworker.py`, `_maybe_forward_htlc` (blinded branch)

The relay reads only `payment_relay`; BOLT-04:325-335 also requires checking `payment_constraints` (`max_cltv_expiry`, `htlc_minimum_msat`, TLV type 12) and `allowed_features` (type 14). Without them, a relayed HTLC that violates the path's own constraints is forwarded anyway. Add the checks before computing `next_amount_msat_htlc`.

### [ ] M4 — `next_node_id` next-hop not supported
**File:** `electrum/lnonion.py`, `ProcessedOnionPacket.next_chan_scid`

Only `short_channel_id` is read from recipient_data; a blinded hop specifying `next_node_id` (TLV type 4) instead yields `next_chan_scid is None` → `INVALID_ONION_PAYLOAD`, failing a well-formed route. The mutual-exclusion MUST (error if both `short_channel_id` and `next_node_id` present) is also unenforced. Resolve `next_node_id` → channel when scid is absent; reject if both present.

---

## 🟡 Low / nits

### [ ] L1 — Wrong failure code for blinded-path errors
Blinded failures (missing `current_path_key` → `get_ecdh(None)`, decrypt failures, etc.) surface as generic codes instead of the mandated `invalid_onion_blinding` (`0x8000|0x4000|24`). The uniform error exists precisely so a failure doesn't leak the node's position in the path. Map blinded-path onion failures to `INVALID_ONION_BLINDING`.

### [ ] L2 — Unused imports in `lnpeer.py`
`get_ecdh` (line 24) and `decrypt_onionmsg_data_tlv` (line 38) are imported but never referenced (the decryption moved into `process_onion_packet`). Drop them.

### [ ] L3 — Redundant double-decrypt in `onion_message.py`
`process_onion_packet` now populates `blinded_path_recipient_data`, but `process_onion_message_packet` re-derives the shared secret and decrypts again (and the `payload['encrypted_recipient_data'][...]` access is unguarded → `KeyError` on a malformed message). Reuse the already-decrypted field.

### [ ] L4 — Cosmetic
- `def  _get_from_payload` has a double space (`electrum/lnonion.py`).
- `UpdateAddHtlc._validate` doesn't check `path_key` (33-byte point), though the wire decoder enforces length downstream.

---

## ✅ Verified correct (ruled out — no action needed)

- Intro-point uses the **real** node key; non-intro hops use the **blinded** key. Both ECDHs correct.
- `next_path_key` uses `recipient_data_shared_secret` (the right ssᵢ), not the onion ss. `E_{i+1}=SHA256(E_i‖ss_i)·E_i` correct.
- `onion_message.py` refactor is behaviorally equivalent to the old explicit `blinding_privkey` call.
- `_check_accepted_final_htlc`: no unbound-`payment_secret_from_onion` path; `allowed_payload_keys` matches spec line 343.
- TLV nestings correct: `path_id`→`data`, `short_channel_id`→`short_channel_id`, `total_amount_msat`→`total_msat`.
- `payment_relay.get(...)` cannot return `None` (TLV reader populates all fields or raises) — no `None * int` crash.
- **All four outer-onion** `_process_incoming_onion_packet` call sites pass `path_key`; trampoline-onion sites correctly don't.
- `ProcessedOnionPacket`'s new required field `blinded_path_recipient_data` has a single construction site — no other constructor breaks.
- `UpdateAddHtlc.path_key` round-trips through `astuple`/`from_tuple`; old 5-tuples stay compatible via the default.
- `@staticmethod`→instance change on `_check_accepted_final_htlc` is safe (single `self.` call site, `lnpeer.py` ~2258).
- `update_add_htlc_tlvs` send-kwarg / `payload["update_add_htlc_tlvs"]` read-key are both correct (TLV streams keyed by type-name).
- Newly attaching the TLV stream to `update_add_htlc` decodes/encodes the no-TLV case fine; the stricter rejection of unknown *even* TLVs is spec-correct ("it's ok to be odd").

---

## Suggested order of work

1. **H1** (fee formula + guard) — required before blinded forwarding can interop.
2. **M1** (cache key) — cheap, high-value hardening.
3. **L2** (unused imports) — trivial cleanup.
4. **M2 / M3 / M4 / L1** — spec-compliance for forwarding; do together when wiring up real forwarding.
5. **L3 / L4** — cleanup.
