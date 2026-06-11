# Review: `f5053da71` — onion_message: perform a direct peer connection for sending request

- **Commit:** `f5053da7104d9080a9419ca81fd6aef83bc2b77d`
- **Author:** Sander van Grieken — Mon Nov 24 15:16:20 2025 +0100
- **Branch:** `bolt12_2` (not merged to `master`; `master` is the pre-commit lineage)
- **Files:** `electrum/onion_message.py`, `electrum/simple_config.py`, `tests/test_onion_message.py`
- **Reviewed:** the actual post-commit tree, not the working copy.

## Verdict

**Reasonable and a net improvement — but only for the single-destination case.** The headline goal in the commit message ("when we have tried *all* blinded paths…") is **not** actually achieved by the control flow: for ≥2 destinations the new bookkeeping is unreachable dead code, and behavior is unchanged from before.

## What it does

1. Adds a config toggle `ONION_MESSAGE_OPEN_DIRECT_CONNECTIONS` (default `True`) with a clear privacy rationale.
2. Makes `_send_pending_message` async and wraps `send_onion_message_to` in `try/except NoRouteFound`. On `NoRouteFound` it marks the destination as failed (`route_not_found_for[dest_index] = True`) and — *if all destinations have failed* and the toggle is on and a `peer_address` hint exists — opens a direct connection via `add_peer` instead of re-raising. Otherwise it re-raises.
3. Removes the old direct-connect block from `process_send_queue`.

## What was there "before"

The pre-commit code already did a direct connection, in `process_send_queue`:

```python
except BaseException as e:
    req.future.set_exception(copy.copy(e))            # <-- request already FAILED here
    if isinstance(e, NoRouteFound) and e.peer_address:
        await self.lnwallet.lnpeermgr.add_peer(str(e.peer_address))   # <-- too late for THIS request
```

The old version called `add_peer` **after** `set_exception` had already failed the request, and there was no resubmit afterward (resubmit only happens in the `else`/success branch). So the connection it opened was orphaned — it could only help a *later, separate* request to the same node (if some higher-level caller retried).

**The new code is a genuine improvement here**: it connects *before* failing and then lets `process_send_queue` resubmit, so the same request is retried over the now-direct connection and can actually succeed. This is the real win, and it's correct for a single destination.

There's also a quiet robustness fix: in the old code, if `add_peer` *raised* inside the `except` handler of `process_send_queue`, it would propagate out of the `while` loop and tear down the entire send-queue task. In the new code `add_peer` runs inside `_send_pending_message`, so a raise is caught by `process_send_queue` and only fails the one request. Good.

## Main issue — the multi-path fallback is unreachable (`electrum/onion_message.py:733-740`)

```python
except NoRouteFound as e:
    req.route_not_found_for[dest_index] = True
    if all(req.route_not_found_for) and self.send_direct_connect_fallback and e.peer_address:
        ... add_peer ...
    else:
        raise
```

Trace it for **N ≥ 2** destinations (`route_not_found_for = [None, None]`):

- Attempt 1 → dest index 0 → `NoRouteFound` → `route_not_found_for = [True, None]` → `all([True, None])` is **False** → `raise`.
- `process_send_queue` catches it → `set_exception` → request is **permanently failed**; `_wait_task` removes it. There is no resubmit (resubmit is only in the no-exception `else` branch).
- Attempt 2 **never happens**, so index 1 is never tried and `all(...)` is never True.

`all(req.route_not_found_for)` can therefore only ever be satisfied when there is exactly **one** destination. For multiple blinded paths the request dies on the first path's `NoRouteFound` — identical to the old behavior — and the `route_not_found_for` list is pure overhead. The `TODO: this will only attempt direct connection to the last blinded path ip node` comment is moot: it never reaches *any* path's direct connection for N≥2.

**Root cause:** the code conflates "this path failed, try the next one" with "fail the whole request." To actually deliver the stated goal, an intermediate `NoRouteFound` (when `not all(...)`) should let the round-robin advance — i.e. return without raising so `process_send_queue` resubmits and `get_next_destination` moves to the next path — and only the all-paths-exhausted case should trigger direct-connect or final failure. (That in turn raises the question of how the final "all failed, no fallback" case should fail — fast `NoRouteFound` vs. eventual `Timeout` — which needs a deliberate decision.)

This is purely forward-looking right now: there are **no production callers** of `submit_send` on the branch yet (only tests), and `get_next_destination` round-robin + the class docstring make multi-path a clearly intended BOLT12 use case. So it's worth fixing before consumers are wired up, but it isn't breaking anything today.

## Secondary observations

- **`NoRouteFound` → `Timeout` substitution, and no reset of `route_not_found_for`.** For a single dest with fallback on, once index 0 is marked `True` it stays `True`; every subsequent retry re-enters the `all(...)` branch and never re-raises. So the request can no longer fail fast with `NoRouteFound` — it ends in `Timeout` (or in the `add_peer` exception if the connection itself fails). The new `run_test5`/`t5_1` correctly documents this (now expects `Timeout`). It's a deliberate trade-off, but callers that branched on `NoRouteFound` should be aware. Also note `add_peer` is retried on every round; harmless (`_add_peer` short-circuits if already connected) but worth knowing.

- **Default `True` privacy trade-off.** Defaulting to opening direct connections (revealing IP to the destination/introduction point) is debatable for a privacy-sensitive wallet. It's strictly better than the old unconditional behavior since there's now a toggle, and `add_peer` is proxy-aware (skips DNS when a proxy is set, connects over Tor), so the long-desc's "unless a proxy like Tor is used" caveat holds. Just flagging the default for a deliberate call.

- **`str(e.peer_address)` round-trip is correct.** `LNPeerAddr.__str__` → `pubkey_hex@host:port`, and `add_peer` parses exactly that via `extract_nodeid` + `split_host_port`. Fine.

- **Test gap.** `run_test5` covers single-dest direct-connect (on/off) well; `run_test6` covers multi-dest round-robin but only when *all* paths have routes (both are direct peers) — i.e. it exercises round-robin on reply-timeout, never `NoRouteFound`. The multi-path-all-fail → fallback scenario (the headline) is untested, which is why the dead-code path slipped through green tests.

- **Nit:** the truncated `# NOTE: above, when passing the caught exception … leads to GeneratorExit() in` comment in `process_send_queue` is now dangling but it's pre-existing, not from this commit.

## Recommendation

Land-worthy as an incremental reliability win for single-destination sends, *if* you either:

- **(a)** fix the multi-path control flow so intermediate `NoRouteFound`s resubmit instead of failing, and only fall back / fail once all paths are exhausted (plus a multi-path test); **or**
- **(b)** drop the `route_not_found_for`/`all(...)` machinery and the "all blinded paths" wording until multi-path is genuinely handled — right now the code promises more than it does.

## Open follow-ups

- [ ] Decide between fix (a) and trim (b).
- [ ] If (a): define the final-failure semantics when all paths fail and fallback is off/unavailable (`NoRouteFound` fast-fail vs. `Timeout`).
- [ ] Add a multi-path-all-fail test exercising the fallback.
- [ ] Confirm the desired default for `ONION_MESSAGE_OPEN_DIRECT_CONNECTIONS` (currently `True`).
