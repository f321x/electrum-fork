# Shared Nostr connection manager — design

Date: 2026-09-29
Repos: Electrum (branch `nostr_py`), electrum-aionostr (new branch `relay_pool` off `master` ad49908)

## 1. Goal

Electrum uses Nostr (via our electrum-aionostr library) for submarine swaps (client and
server), Nostr Wallet Connect (NWC plugin) and multisig PSBT cosigning (psbt_nostr plugin).
Each of these instantiates its own `aionostr.Manager`, so the same relay is connected several
times, switching features reconnects, and proxy/SSL/logging/restart logic is duplicated.

Goal: a single Nostr connection manager, owned by the `Network` singleton, that all of Electrum
(core and plugins) uses to query and publish events. It multiplexes one websocket per relay URL
across all consumers, keeps per-consumer relay sets, and centralises proxy/config handling.

### Success criteria

- At most one websocket per relay URL per process, shared by all consumers.
- One API for all consumers: `network.nostr.open_session(...)`.
- Proxy changes and default-relay config changes are handled in one place.
- Closing and reopening a feature (e.g. the swap dialog) within the linger window reuses live
  sockets instead of reconnecting.
- Existing tests pass; new lean tests cover the load-bearing pool/relay behaviour.

### Constraints (agreed)

1. **Lazy**: nothing connects to Nostr until a consumer opens a session (Qt asks for consent
   before using Nostr for swaps; this must stay meaningful).
2. **Scoped**: a consumer's subscriptions and publishes only go to that consumer's relays
   (e.g. psbt DMs never go to relays chosen by a swap provider).
3. **Wire-compatible**: swap, NWC and psbt message formats and event kinds are unchanged.
4. **Offline mode unchanged**: no `Network` → no `network.nostr` → Nostr features unavailable
   (consumers already guard for this).
5. **AUTH identity**: shared connections answer NIP-42 AUTH challenges with a fresh random key
   per websocket, never with a consumer's key. Accepted consequence: relays can link identities
   that share a socket (they largely can today via IP), and psbt_nostr no longer authenticates
   as the cosigner key (recipient-restricted DM reads on AUTH-gated relays won't work; they
   mostly don't today because REQs are not re-sent after AUTH, review F11).
6. **Idle connections linger** for a grace period (180 s) after their last session releases
   them, then close.
7. **Lean tests**: only load-bearing logic, real objects / an in-process relay instead of
   mocks; no tests for trivial wiring.

### Current state (for reference)

| Consumer | Lifetime | Key(s) | Relays | Special handling |
|---|---|---|---|---|
| Swap client `NostrTransport` | short (per dialog/command) | random per transport | `NOSTR_RELAYS` ∪ provider's announced relays | live relay update when provider's offer lists new relays; rebroadcasts offers; touches `Relay` objects directly |
| Swap server `NostrTransport` | long (swapserver plugin) | lnworker nostr key | `NOSTR_RELAYS` | announces `NOSTR_RELAYS` in its offer |
| NWC `NWCServer` | long (per wallet) | per-connection secrets; random AUTH key | `NOSTR_RELAYS` ∪ {`NWC_RELAY`} | `refresh_manager()` rebuilds the Manager when relays drop (works around F13); own `proxy_set` handler |
| psbt_nostr `CosignerWallet` | long (per multisig wallet) | xpub-derived cosigner key (also AUTH) | `NOSTR_RELAYS` | opens a **new Manager per PSBT sent**; own `proxy_set` handler; blocks consumption on `pending.wait()` |

Review references (Fxx/Nxx) are from `security-review-2026-09-29.pdf` in the aionostr worktree.

## 2. Architecture overview

```
electrum-aionostr 0.2.0                         Electrum
┌─────────────────────────────────────┐        ┌────────────────────────────────────────┐
│ RelayPool                           │◄───────│ electrum/nostr.py: NostrManager         │
│  ├─ default relays                  │        │  (network.nostr; config, proxy, SSL,   │
│  ├─ one supervised Relay per URL    │        │   logging, lifecycle)                   │
│  ├─ refcount + linger close         │        └──────────────┬─────────────────────────┘
│  └─ shared aiohttp ClientSession    │                       │ open_session()
│ NostrSession (per consumer)         │◄──────────────────────┤
│  ├─ relay set = defaults ∪ extras   │          swap client / swap server / NWC / psbt_nostr
│  ├─ get_events() / publish()        │
│ Manager (thin compat wrapper)       │
└─────────────────────────────────────┘
```

All pool/session/relay objects live on one asyncio event loop (Electrum's). Callers on other
threads keep using `asyncio.run_coroutine_threadsafe`, as today.

## 3. aionostr: supervised `Relay`

Each `Relay` has **one supervisor task** that exclusively owns the connection.
States: disconnected → connecting → connected → (on drop) backoff → connecting …; `closed` is
terminal.

Supervisor loop:
1. Connect via the pool's **current** `ClientSession` (read on every attempt, so a
   `set_proxy` takes effect on the next attempt) with `ws_connect(..., heartbeat=30)` so
   half-open connections are detected (F12), bounded by the pool's current `connect_timeout`.
2. On connect, in **one synchronous step with no `await` in between**: generate a fresh random
   AUTH key for this websocket, take a snapshot of the active subscriptions, and mark the socket
   open for REQ/CLOSE. From that moment `add_subscription()` / `remove_subscription()` send
   their own REQ/CLOSE. Then replay REQs from the snapshot, skipping subscriptions removed in
   the meantime, and set the `connected` event. Live subscription state is never iterated
   across an `await` (F02/F32).
3. Run the receive loop until the socket closes/errors, then clear `connected`, close the ws,
   notify subscriptions that this relay disconnected, and resolve pending publish waiters of
   that socket with `accepted=False, message='disconnected'` (F15).
4. Back off (exponential with full jitter, base ~1 s, cap ~300 s; reset after being connected
   for a healthy period, ~60 s) and go to 1. Backoff parameters are class attributes so tests
   can shrink them.
5. Relays that fail at startup keep retrying in the background; they are never dropped (F13).

Rules:
- `send()` never reconnects (F02/F03). A REQ added while the socket is not open is only
  recorded; the supervisor sends it in step 2. `remove_subscription()` removes local state
  first, then sends CLOSE best-effort (only if the socket is open, short timeout; F07).
- `close()` is idempotent, cancellation-safe, enters `closed`, cancels the supervisor, closes
  the ws, fails pending publishes (F17/N09/N10/F24).
- `wake()`: if the supervisor is sleeping in backoff, stop sleeping and attempt to connect now.
  Rate-limited to at most one early attempt per ~10 s per relay, so busy callers cannot hammer
  a dead relay. Used by the pool when a session needs the relay (§4).
- `restart()`: cancels whatever the supervisor is doing (backoff sleep, in-flight `ws_connect`,
  receive loop), resets the backoff and reconnects immediately. Used by `RelayPool.set_proxy`.
- AUTH: on `["AUTH", challenge]` sign a kind-22242 event with the per-websocket random key (or
  the pool's `auth_private_key` if one was given, see §4) and send it.

Receive loop:
- Branch on the ws frame type: TEXT → handle; BINARY → ignore; CLOSE/CLOSING/CLOSED/ERROR →
  return (F16). Keep the existing per-message processing sleep and the 64000-char message cap.
- **Per-message isolation (F01, minimal part):** each TEXT frame is handled in its own
  try/except; a malformed message is logged at debug level and dropped, with **no sleep**.
  Event validation itself is not changed.
- **Non-blocking delivery (F06):** events are handed to the subscription's sink with
  non-blocking calls. Subscription event queues are bounded (~1000); on overflow the event is
  dropped for that subscription only and a warning is logged. EOSE and disconnect notifications
  are tracked as per-relay state outside that queue, so they can never be dropped. A consumer
  that stops reading (psbt_nostr waiting for the user) can therefore never stall other
  consumers on the same socket.

Publishing:
- `Relay.publish(event, timeout) -> PublishResult(url: str, accepted: bool, message: str)`.
  Sends EVENT and waits for the matching OK with a timeout (F15). OK frames are parsed strictly
  (`["OK", <id str>, <bool>, <str>]`), late/duplicate OKs never touch a done future, and
  concurrent publishes of the same event id share one waiter (F26). Not connected → immediate
  `PublishResult(accepted=False, message='not connected')`.

## 4. aionostr: `RelayPool`, `NostrSession`, helpers

New module `pool.py`. Exported from the package top level.

```python
pool = RelayPool(origin='aionostr', log=None, ssl_context=None, proxy=None,
                 connect_timeout=5, linger_sec=180, auth_private_key=None)
pool.set_default_relays(urls)                       # sync; sessions using defaults follow
session = pool.open_session(use_default_relays=True, extra_relays=(), name='')  # sync
await pool.set_proxy(connector_or_None, connect_timeout=10)  # new ClientSession; relays restart
await pool.close()                                  # also: async with RelayPool(...) as pool
```

`RelayPool`:
- Holds exactly one `Relay` per normalized URL and one shared aiohttp `ClientSession` (created
  on first use with the given proxy connector; the pool owns the connector).
- Tracks which sessions use each relay. When no session uses a relay any more, a linger timer
  (`linger_sec`) starts; reacquiring the relay before it fires cancels it (no reconnect).
  `linger_sec=0` closes immediately. When the timer fires, the relay is removed from the URL
  map **synchronously, before** awaiting its `close()`; acquisition never returns a closing or
  closed relay and creates a fresh one instead.
- The pool calls `relay.wake()` (§3) when a session acquires a relay (`open_session`,
  `set_extra_relays`, `set_default_relays`) and when `wait_connected()` or `publish()` starts
  waiting on a relay set with no connected relay. So a short-lived consumer reusing a relay that
  a long-lived session keeps in backoff (e.g. after a Wi-Fi drop) connects right away.
- `set_default_relays(urls)` recomputes the relay set of every session opened with
  `use_default_relays=True`; their active subscriptions follow (see below).
- `set_proxy(connector, *, connect_timeout)` is serialized by a lock. It creates a new
  `ClientSession`, updates the pool's `connect_timeout` (read by supervisors on every attempt
  and by `publish()` as its default), calls `restart()` on every relay (active subscriptions are
  re-sent on reconnect), and only then closes the old session/connector.
- Owns all background tasks (relay supervisors, linger timers, publish tails). Task exceptions
  are logged via done-callbacks, never silently lost (F14); `close()` closes all sessions (see
  Closing), cancels and awaits all tasks, and closes the `ClientSession`.
- `auth_private_key`: optional fixed AUTH key (used by the `Manager` wrapper to keep the CLI's
  `NOSTR_KEY` behaviour). Electrum never sets it.

`NostrSession` (consumer handle; all methods on the loop):

```python
session.name
session.relays                                  # frozenset[str]: defaults (if used) ∪ extras
session.connected_relays() -> list[str]
await session.wait_connected(timeout=None) -> bool   # any relay of the set connected
await session.set_extra_relays(urls)
async for ev in session.get_events(*filters, only_stored=True, single_event=False,
                                   filter_future_events_sec=3600): ...
await session.publish(event, relays=None, timeout=None) -> PublishResult
await session.close()
```

Subscriptions:
- Each `get_events()` call creates one subscription with a random sub-id, REQ'd on every relay
  in the session's set (identical filters from different sessions are **not** merged).
- Events are de-duplicated across relays with a seen-id set that is **per subscription**, LRU,
  and bounded well above filter limit × relay count (10 000) (F09). Today's set is unbounded
  per subscription; the bound must not let a relay trivially evict and re-deliver an id.
- Relay-set changes (extras or defaults): added relays get REQs for all active subscriptions;
  removed relays get CLOSE; the relay's refcount is updated (linger applies). Same
  no-live-iteration-across-await rule as §3 step 2.
- `only_stored=True` completes when every relay that received the REQ has sent EOSE,
  disconnected, or left the session's set. A relay that connects mid-query is included.
  `EOSE_TIMEOUT_SEC` stays what it is today: a **per-item inactivity timeout for the whole
  query** (no event and no completion for 60 s → the query ends normally), so a relay that stays
  connected but withholds EOSE cannot hang it.
- `only_stored=False` streams until the consumer stops iterating / cancels / closes the
  session. It does **not** end because zero relays are connected (F13).
- Leaving the generator (break, exception, GC) closes the subscription, as today.
- Same `filter_future_events_sec` check as today.

Publishing:
- Targets every relay of the set (or the given subset, which must be ⊆ the session's relays).
  Relays connected at call time get the event immediately; relays of the target set that
  connect before the publish deadline also get it (today every Manager connects to all relays
  before its first publish, and consumers rely on the event reaching all of them, e.g. a swap
  request must reach a relay the server reads). An empty relay set fails immediately (F27).
- `timeout` defaults to the pool's current `connect_timeout` and bounds both waiting for a
  connection and waiting for the acknowledgement.
- Returns the `PublishResult` of the **first acceptance**; sending to late-connecting relays
  and their acknowledgements continue in pool-owned background tasks until the deadline.
- Raises `PublishError(results)` when every relay rejected the event or none acknowledged it in
  time (F05). `str(PublishError)` is human-readable (the GUIs show it).
- Accepts an `Event` or a dict event (the dict's own `id` is what gets published and returned).

Closing:
- `session.close()` and `pool.close()` (which closes all of its sessions) wake every live
  `get_events()` of the affected sessions; those generators **return normally**.
- Removing a subscription, or calling `session.close()`, on an already closed session or pool
  is a silent no-op (generator `finally` blocks and GC finalization must not raise).
- `publish()`, `get_events()`, `set_extra_relays()`, `wait_connected()` after close raise
  `SessionClosed` / `PoolClosed`.

Errors: `PublishError`, `SessionClosed`, `PoolClosed`.

Helpers and compatibility:
- New public `create_event(private_key, *, kind, content='', tags=None, created_at=None) ->
  Event` (hex/bytes/`PrivateKey`), replacing the event-building part of the private
  `_add_event` that all Electrum consumers use today.
- `Manager` becomes a thin wrapper: a private `RelayPool(linger_sec=0)` plus one session with
  no defaults and `extra_relays=relays`. It keeps `connect()`, `close()`, `get_events()`,
  `add_event()` (Event or dict), `update_relays()` (→ `set_extra_relays`), and async-with.
  `connect()` returns once every relay has either connected or failed its first attempt
  (bounded by `connect_timeout`), preserving today's "all relays tried before the first query"
  semantics for `get_anything`. `Manager.relays` stays a list of objects with `.url`, one per
  normalized URL, available before `connect()` (the kept dedup test relies on it).
- `get_anything` (including `stream=True`), `add_event`, `add_events` and `_add_event` keep
  working through the wrapper.
- CLI: `aionostr mirror` and `aionostr bench` are **already broken** today (`mirror` calls
  `Manager.add_event(check_response=True)`, which does not exist; `bench` calls
  `Relay(url, client=...)`). Fix `mirror` (drop `check_response`) and port `bench`'s
  `adds_per_second` to `RelayPool`/`NostrSession`.
- Version 0.2.0 (breaking: `Relay`/`Manager` internals change). README and changelog updated.

## 5. Electrum: `NostrManager` (`electrum/nostr.py`)

Created in `Network.__init__` as `network.nostr`. Never connects on its own; the `RelayPool` is
created on the asyncio loop on the first `open_session()`.

```python
session = network.nostr.open_session(name='nwc', extra_relays=[config.NWC_RELAY])
# use_default_relays=True by default; must be called on the asyncio loop (asserted)
```

Responsibilities:
- **Defaults**: `pool.set_default_relays(config.get_nostr_relays())` on pool creation and on a
  new `nostr_relays_changed` util callback. `SimpleConfig` has no ConfigVar change hooks, so the
  callback is triggered by the code paths that edit relays: `SimpleConfig.add_nostr_relay` /
  `remove_nostr_relay`, the Qt Nostr tab's reset button, the QML `nostrRelays` setter, and
  `Commands._setconfig` when the key is `NOSTR_RELAYS` (it already special-cases keys; a daemon
  configured via `setconfig` must pick up relay changes without a restart, as it does today).
- **Pool creation**: the pool is created with the **current** proxy
  (`make_aiohttp_proxy_connector(network.proxy, ssl_context)` if `network.proxy.enabled`, else
  `None`) and the matching connect timeout (10 s with proxy / 5 s without). `proxy_set` fires
  inside `Network.__init__` and on every settings change, long before the first session; a
  `proxy_set` while no pool exists is a no-op.
- **Proxy changes**: on `proxy_set`, build the connector the same way and call
  `pool.set_proxy(connector, connect_timeout=10 if enabled else 5)`.
- **Setup**: one SSL context (`ca_path`), an `aionostr` child logger at INFO, `linger_sec=180`.
- **Lifecycle**: `Network.stop(full_shutdown=True)` awaits `network.nostr.stop()` (closes the
  pool, unregisters callbacks); `open_session()` after `stop()` raises. A network restart with
  `full_shutdown=False` (proxy or oneserver change) does not touch Nostr; the proxy change
  reaches it via `proxy_set`.

Not included: relay status in the Qt Nostr tab, a Nostr RPC command.

## 6. Consumer migrations

### Swap `NostrTransport` (client and server)
- `main_loop` opens a session instead of a Manager: client `name='swap-client'`,
  `extra_relays=self._last_swapserver_relays or []`; server `name='swap-server'`, no extras.
- A small task sets `is_connected` once `session.wait_connected()` returns (even if relays come
  up late). `stop()` closes the session (relays linger for the next transport).
- `update_relays()` → `session.set_extra_relays(offer.relays)` (plus persisting them, as today).
- `rebroadcast_event()` → `session.publish(event, relays=[connected relays not in the provider's
  relays (normalized)])`, `PublishError` ignored (debug log).
- `publish_offer()` / `send_direct_message()` build events with `create_event()` and catch
  `PublishError` instead of `asyncio.TimeoutError`. **Retries re-send the same signed event**
  (today each retry signs a new one, so the server can process duplicates; F19).
- Remove `relay_manager`, `get_relay_manager()`, `ssl_context`, the nsec re-encoding.
- The per-transport random keypair stays (DM `#p` filter + signing).

### NWC `NWCServer`
- Remove `get_relay_manager()`, `refresh_manager()`, `on_event_proxy_set()`, `self.manager`,
  `ssl_context`.
- `run()` opens one session (`name='nwc'`, `extra_relays=[NWC_RELAY]`) once its existing
  preconditions hold, keeps it across handler restarts, closes it on plugin shutdown.
- Before starting the handler taskgroup, `run()` awaits `session.wait_connected()` with a
  timeout and retries every 30 s like today's `refresh_manager()` gate, so the first info
  events are not published into a pool whose sockets are still connecting.
- `restart_event_handler()` still restarts the handler taskgroup when the client set changes
  (the `authors` filter depends on it).
- `send_encrypted_response()`, `publish_notification_event()` and the info-event loop publish
  via the session and catch/log `PublishError` so a failed publish no longer tears down the
  handler (F19). A failed info-event publish is retried after ~60 s instead of waiting the full
  24 h rebroadcast interval (today the failure restarts the handler, which republishes after
  60 s).
- When the pool closes (daemon shutdown closes the network before plugins), the
  `handle_requests()` generator returns normally and `run()` falls back to its precondition
  wait; no extra handling needed.

### psbt_nostr `CosignerWallet`
- One session per multisig wallet (`name='psbt'`), opened at the very start of `main_loop()`
  (on the loop, **before** the wallet-sync wait), shared by `check_direct_messages()` and
  `send_direct_messages()`. Its lifetime does not depend on the `check_direct_messages()` task;
  it is closed only in `stop()`/`close()`. So sending works before the wallet has synced, as it
  does today. `send_direct_messages()` raises a clear error if there is no network/session.
- Remove `nostr_manager()`, `ssl_context`, `on_event_proxy_set()`. The Qt/QML subclasses keep
  their `register_callbacks()` (they also listen to `psbt_nostr_received`).
- `send_direct_messages()` publishes via the session and lets `PublishError` propagate; the Qt
  and QML send paths already show `str(e)` for any exception, so users now see a failure when
  every relay rejected the PSBT instead of a false success (F05).
- `check_direct_messages()` keeps waiting for wallet sync and keeps `pending.wait()` (safe now
  thanks to non-blocking delivery).

### Unchanged
Swap dialogs, `qeswaphelper`, `get_submarine_swap_providers` (they only use the transport).

## 7. Testing (lean, load-bearing only)

aionostr — an in-process test relay (aiohttp websocket server on localhost) that implements
REQ/EVENT/CLOSE/EOSE/OK and can be told to refuse connections, drop sockets, send garbage /
binary frames, answer `OK false`, withhold OK/EOSE. Tests:
1. Two sessions on the same URL share one websocket; each gets its own events.
2. Scoping: a session's REQs/EVENTs never reach relays outside its set.
3. Linger: reuse within the window (no new connection); close after it expires.
4. Socket drop → reconnect → active subscriptions re-REQ'd, events flow again; closed ones are
   not re-sent.
5. Relay down at start → comes up later → the session's subscription receives events. With a
   large backoff configured, a new session acquiring the relay (wake) connects within
   `connect_timeout` once the relay is back.
6. A subscription nobody reads does not stall another subscription on the same socket; a
   malformed message does not stall the socket.
7. Publish: first acceptance returns; all `OK false` → `PublishError`; no OK → `PublishError`
   after timeout; empty relay set fails immediately; a relay of the set that connects shortly
   after the call still receives the event.
8. `only_stored` completes with one relay of the set down, and with one connected relay that
   withholds EOSE (via the inactivity timeout).
9. `set_default_relays` / `set_extra_relays` move subscriptions; `set_proxy` restarts relays
   (including one sitting in backoff) and subscriptions survive.
10. `close()` releases a consumer blocked in `get_events()` (generator returns normally) and
    leaves no running tasks and no open sockets.
Existing `Manager` tests are reduced to behaviour the wrapper still guarantees (relay dedup,
subscription closed on generator exit, stored-only vs streaming); tests of removed internals
(`monitor_queues`) are deleted.

Electrum:
- Swap transport: a retry re-sends the same event id (small fake session object, no mock
  chains). This is the only new Electrum test; `NostrManager` is thin wiring and is not
  unit-tested (constraint 7).
- Existing swap/commands tests need no changes: they patch `NostrTransport.main_loop` /
  `__aexit__` and `create_transport`, none of which the migration removes.
- Full `pytest tests` passes.

Manual check against real relays (if the environment has access, otherwise steps for the
user): open, close, reopen a swap transport and run NWC + psbt concurrently; logs show one
connection per relay and no reconnects.

## 8. Rollout

- aionostr branch `relay_pool` off `master` (ad49908) in `~/local-dev/electrum-aionostr`;
  version 0.2.0.
- Electrum branch `nostr_py`: `contrib/requirements/requirements.txt` →
  `electrum_aionostr>=0.2.0,<0.3`. The deterministic-build hash
  (`contrib/deterministic-build/requirements.txt`) can only be updated after 0.2.0 is published.
- Development: `pip install -e ~/local-dev/electrum-aionostr` (branch `relay_pool`).
- Logical commits in each repo, no AI attribution trailers.

## 9. Out of scope

Receive-loop validation hardening beyond per-message isolation (F10, N01–N05), filter matching
of received events (F08), CLOSED handling and re-REQ after AUTH (F11), resume-with-`since`
after reconnect (F25), merging identical filters across sessions, swap offer validation (F04),
NWC replay protection (F20), swap RPC timeouts (F21), relay status UI, Nostr RPC command.

## 10. Risks

- Relays cap subscriptions per connection (commonly 10–20). Expected concurrent subs per
  socket: swap client 2, swap server 1, NWC 1 per wallet, psbt 1 per multisig wallet — well
  below typical caps, but many open multisig wallets could approach them.
- Sharing a socket makes identity linkage on a relay certain (accepted, constraint 5).
- Electrum and aionostr must be released in lockstep (requirements pin).
