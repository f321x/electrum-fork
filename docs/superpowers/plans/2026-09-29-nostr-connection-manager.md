# Shared Nostr Connection Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-feature `aionostr.Manager` instances (swaps, NWC, psbt_nostr) with one process-wide pool on `network.nostr` that shares one websocket per relay between all consumers.

**Architecture:** electrum-aionostr 0.2.0 gets a supervised `Relay` (one reconnecting task per connection), a `RelayPool` (one `Relay` per URL, reference-counted, idle relays linger then close) and `NostrSession` (a consumer's relay set, subscriptions and publishing); the old `Manager` becomes a thin wrapper. Electrum gets `electrum/nostr.py` (`NostrManager`, created by `Network`) which configures the pool (proxy, SSL, default relays, linger) and hands out sessions; the three consumers are migrated to sessions.

**Tech Stack:** Python ≥ 3.10, asyncio, aiohttp websockets (client and, for tests, server), electrum_ecc, pytest/unittest.

**Spec:** `docs/superpowers/specs/2026-09-29-nostr-connection-manager-design.md` (Electrum repo, branch `nostr_py`). Read it before starting; this plan argues from it.

## Global Constraints

- Two repos. Library: `~/local-dev/electrum-aionostr`, new branch `relay_pool` off `master` (ad49908); it is a git worktree (the `master` branch is checked out in another worktree, do not touch it). Electrum: `/home/user/electrum-vm`, branch `nostr_py`.
- Python ≥ 3.10 for both: no `asyncio.TaskGroup`, no `asyncio.timeout()` (3.11+). Use `asyncio.wait_for`, `asyncio.wait`, `asyncio.gather`.
- Do **not** `pip install` anything into the user's environment (`~/.local` holds electrum-aionostr 0.1.0 used by another checkout). Run everything against the library source via `PYTHONPATH`:
  - library tests: `cd ~/local-dev/electrum-aionostr && PYTHONPATH=src python3 -m pytest -q tests`
  - Electrum tests: `cd /home/user/electrum-vm && PYTHONPATH=/home/user/local-dev/electrum-aionostr/src python3 -m pytest -q <tests>` (`python3 -m pytest` from the repo root makes `import electrum` pick up this checkout).
- Lint gate (Electrum CI, use for both repos, the library's `delegation.py` has 2 pre-existing W293 warnings, ignore those):
  `python3 -m flake8 <paths> --count --select="E9,E101,E129,E273,E274,E703,E71,E722,F5,F6,F7,F8,W191,W29,B,B909" --ignore="B007,B009,B010,B036,B042,F541,F841" --show-source --statistics`
- Tests are lean and load-bearing only, no mock chains ("no mock party", user request). Use the in-process `LocalRelay` instead of mocked websockets. Do not add tests beyond the ones in this plan without asking.
- Wire compatibility: event kinds, tags and message formats of swaps, NWC and psbt_nostr must not change.
- NIP-42 AUTH is answered with a random key per websocket, never with a consumer's key.
- Idle relay linger in Electrum: `NostrManager.LINGER_SEC = 180`. Connect timeout: 10 s with proxy, 5 s without.
- Commit messages: no `Co-Authored-By` or other AI attribution trailers (user preference). Commit author is the configured git user.
- The spec is committed on `nostr_py` as its own commit (5d70f4505); this plan gets its own `docs:` commit in Task 5 Step 1. Both stay separate from code commits so they can be dropped before a PR.

## Review Focus

These inputs/conditions follow from the spec but no automated test exercises them (tests stay lean per the user's request). Reviewers check them by reading the code; Task 9 has manual checks.

1. **Tor/SOCKS proxy enabled before first use and toggled at runtime.** Expected: the pool is created with the current proxy and every relay reconnects through the new proxy on `proxy_set`; no connection goes out directly. Pinned: code review of `NostrManager._get_proxy`/`on_event_proxy_set` (Task 5) and `RelayPool.set_proxy`/`_get_client_session` (Task 3); manual check in Task 9 step 5.
2. **A relay that accepts the websocket but then never answers (black hole).** Expected: publishes time out after `connect_timeout` with `PublishError`, stored queries end after `EOSE_TIMEOUT_SEC` of inactivity, aiohttp's 30 s heartbeat eventually drops the socket and the supervisor reconnects with backoff. Pinned: `test_publish_results` (silent relay) and `test_stored_query_does_not_wait_for_down_or_silent_relays` cover the timeouts; the heartbeat is reviewed (`HEARTBEAT_SEC` passed to `ws_connect`).
3. **Swap provider announcing garbage relay lists** (non-ws schemes, whitespace, >10 entries, duplicates in other spellings). Expected: invalid URLs are ignored with an info log, duplicates collapse after `normalize_url`, the rebroadcast exclusion compares normalized URLs. Pinned: `test_relay_changes_and_proxy_switch_keep_subscriptions` (invalid entries ignored), `test_sessions_share_one_connection_per_relay` (spellings collapse).
4. **Daemon shutdown while NWC / psbt_nostr / swap transports hold sessions** (the network, and with it the pool, is stopped before plugins). Expected: live `get_events()` generators return normally, later calls raise `PoolClosed`, no hang and no traceback storm. Pinned: `test_close_releases_waiting_consumers_and_stops_everything`; manual check in Task 9 step 4.
5. **Swap dialog closed while a swap request is in flight** (`transport.stop()` closes the session while `send_request_to_server` waits). Expected: `publish()` raises `SessionClosed`, `send_direct_message` (decorated with `@ignore_exceptions`) returns `None`, the caller gets `SwapServerError`. Pinned: code review of Task 6.

## File Structure

electrum-aionostr (`~/local-dev/electrum-aionostr`):
- `src/electrum_aionostr/util.py` — add `is_valid_relay_url()` (validates untrusted relay URLs).
- `src/electrum_aionostr/event.py` — add `create_event()` (build + sign, any key format).
- `src/electrum_aionostr/relay.py` — **rewritten**: supervised `Relay`, `PublishResult`, `PublishError`, `SubscriptionSink` protocol. The old `Manager` moves out.
- `src/electrum_aionostr/pool.py` — **new**: `RelayPool`, `NostrSession`, `_Subscription`, `RelayInfo`, `PoolClosed`, `SessionClosed`, and (Task 4) the `Manager` compatibility wrapper + `NotInitialized`.
- `src/electrum_aionostr/__init__.py` — exports; `_add_event` uses `create_event`; version 0.2.0.
- `src/electrum_aionostr/cli.py`, `benchmark.py` — fix `mirror`, port `bench` setup to the pool.
- `pyproject.toml` — drop `aiorpcx` (no longer used). `docs/history.md`, `README.md` — changelog and pool usage.
- `tests/relay_server.py` — **new**: `LocalRelay` (in-process relay), `RelayTestCase`, helpers.
- `tests/test_relay.py`, `tests/test_pool.py` — **new**. `tests/test_manager.py` — **replaced**. `tests/test_event.py` — one test added.

Electrum (`/home/user/electrum-vm`):
- `electrum/nostr.py` — **new**: `NostrManager`.
- `electrum/network.py` — create `self.nostr`, stop it on full shutdown.
- `electrum/commands.py`, `electrum/gui/qt/network_dialog.py`, `electrum/gui/qml/qeconfig.py` — fire `nostr_relays_changed` where relays are edited. (Spec §5 also names `SimpleConfig.add_nostr_relay`/`remove_nostr_relay`; their only caller is the Qt Nostr tab, so the event is fired there instead, which keeps `SimpleConfig` free of event-loop calls.)
- `contrib/requirements/requirements.txt` — `electrum_aionostr>=0.2.0,<0.3`.
- `electrum/submarine_swaps.py` + `tests/test_submarine_swaps.py` — swap transport on a session.
- `electrum/plugins/nwc/nwcserver.py` — NWC on a session.
- `electrum/plugins/psbt_nostr/psbt_nostr.py` — psbt_nostr on a session.

How to apply the diffs in this plan: save the block to a file (e.g. `/tmp/task6.diff`) and run `git apply /tmp/task6.diff` in the repo root; `git apply --check` first if unsure. All diffs were generated against the current branch heads and verified to apply.

---

## Part A — electrum-aionostr

### Task 1: `create_event` and `is_valid_relay_url`

**Files:**
- Modify: `src/electrum_aionostr/util.py`, `src/electrum_aionostr/event.py`
- Test: `tests/test_event.py`

**Interfaces:**
- Produces: `electrum_aionostr.event.create_event(private_key: str | bytes | PrivateKey, *, kind: int, content: str = '', tags: list[list[str]] | None = None, created_at: int | None = None) -> Event` (private_key may be hex str, nsec str, 32 raw bytes or `PrivateKey`); `electrum_aionostr.util.is_valid_relay_url(url) -> bool` (takes the raw, un-normalized URL; bare hostnames are valid, other schemes are not).

- [ ] **Step 1: Create the branch**

```bash
cd ~/local-dev/electrum-aionostr
git status --short   # only the untracked security-review PDF is expected
git switch -c relay_pool
```

- [ ] **Step 2: Write the failing test** — apply this diff to `tests/test_event.py`:

```diff
--- a/tests/test_event.py
+++ b/tests/test_event.py
@@ -3,7 +3,7 @@
 import os
 import time
 
-from electrum_aionostr.event import Event, InvalidEvent
+from electrum_aionostr.event import Event, InvalidEvent, create_event
 from electrum_aionostr.key import PrivateKey
 
 class TestEvent(unittest.TestCase):
@@ -73,3 +73,11 @@
 
         self.assertTrue(event.is_expired())
         self.assertEqual(event.expires_at(), expiration_time)
+
+    def test_create_event_accepts_all_private_key_formats(self):
+        key = PrivateKey()
+        for private_key in (key, key.hex(), key.raw_secret, key.bech32()):
+            event = create_event(private_key, kind=4, content='hi', tags=[['p', 'ab' * 32]], created_at=1)
+            self.assertEqual(key.public_key.hex(), event.pubkey)
+            self.assertEqual((4, 'hi', [['p', 'ab' * 32]], 1), (event.kind, event.content, event.tags, event.created_at))
+            self.assertEqual(event, Event.from_json(event.to_json_object()))  # sigcheck passes
```

- [ ] **Step 3: Run it to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest -q tests/test_event.py`
Expected: collection error `ImportError: cannot import name 'create_event'`.

- [ ] **Step 4: Implement** — apply these diffs:

```diff
--- a/src/electrum_aionostr/event.py
+++ b/src/electrum_aionostr/event.py
@@ -7,10 +7,12 @@
 import functools
 from enum import IntEnum
 from hashlib import sha256
-from typing import Optional
+from typing import Optional, Union
 
 from electrum_ecc import ECPrivkey, ECPubkey
 
+from .key import PrivateKey
+
 
 try:
     import orjson
@@ -232,3 +234,33 @@
             content=d["content"],
             sig=sig,
         )
+
+
+def create_event(
+    private_key: Union[str, bytes, PrivateKey],
+    *,
+    kind: int,
+    content: str = '',
+    tags: Optional[list[list[str]]] = None,
+    created_at: Optional[int] = None,
+) -> Event:
+    """Build and sign an event. private_key: hex or nsec str, 32 raw bytes, or a PrivateKey."""
+    if isinstance(private_key, PrivateKey):
+        privkey_hex = private_key.hex()
+    elif isinstance(private_key, bytes):
+        privkey_hex = private_key.hex()
+    elif isinstance(private_key, str) and private_key.startswith('nsec'):
+        privkey_hex = PrivateKey.from_nsec(private_key).hex()
+    elif isinstance(private_key, str):
+        privkey_hex = private_key
+    else:
+        raise TypeError(f"unsupported private key type: {type(private_key)}")
+    pubkey = ECPrivkey(bytes.fromhex(privkey_hex)).get_public_key_bytes()[1:].hex()
+    event = Event(
+        pubkey=pubkey,
+        kind=kind,
+        content=content,
+        tags=[list(tag) for tag in tags] if tags else [],
+        created_at=created_at if created_at is not None else int(time.time()),
+    )
+    return event.sign(privkey_hex)
```

```diff
--- a/src/electrum_aionostr/util.py
+++ b/src/electrum_aionostr/util.py
@@ -1,3 +1,5 @@
+import urllib.parse
+
 from .key import PublicKey, PrivateKey, bech32
 
 NIP19_PREFIXES = ('npub', 'nsec', 'note', 'nprofile', 'nevent', 'nrelay', 'nostr:', 'naddr')
@@ -103,3 +105,22 @@
     if not stripped_url.startswith(('ws://', 'wss://')):
         stripped_url = 'wss://' + stripped_url
     return stripped_url
+
+
+def is_valid_relay_url(url: str) -> bool:
+    """Whether url (as given by a user or a peer, before normalize_url) is a ws:// or wss:// URL
+    with a host. Bare hostnames are accepted, normalize_url() prefixes them with wss://."""
+    if not isinstance(url, str):
+        return False
+    url = normalize_url(url)
+    if any(c.isspace() for c in url):
+        return False
+    try:
+        parts = urllib.parse.urlsplit(url)
+        parts.port  # raises ValueError for an invalid port
+    except ValueError:
+        return False
+    if parts.scheme not in ('ws', 'wss') or not parts.hostname:
+        return False
+    # e.g. 'http://host' would have been turned into 'wss://http://host'
+    return '://' not in url[len(parts.scheme) + 3:]
```

- [ ] **Step 5: Run the tests**

Run: `PYTHONPATH=src python3 -m pytest -q tests`
Expected: `13 passed`.

Sanity check of the URL validator (not a committed test):
Run: `PYTHONPATH=src python3 -c "from electrum_aionostr.util import is_valid_relay_url as v; print([v(u) for u in ['wss://a.b','relay.damus.io','http://x.com','not a url','ws://127.0.0.1:99','wss://x:abc', 5]])"`
Expected: `[True, True, False, False, True, False, False]`

- [ ] **Step 6: Commit**

```bash
git add src/electrum_aionostr/event.py src/electrum_aionostr/util.py tests/test_event.py
git commit -m "event: add create_event helper; util: add is_valid_relay_url"
```

### Task 2: Supervised `Relay` and the in-process test relay

**Files:**
- Create: `tests/relay_server.py`, `tests/test_relay.py`
- Rewrite: `src/electrum_aionostr/relay.py` (the old `Relay` and `Manager` are replaced)
- Modify: `src/electrum_aionostr/__init__.py` (import line only)
- Delete: `tests/test_manager.py` (tests internals that no longer exist; Task 4 adds a new one)

**Interfaces:**
- Consumes: `create_event` (Task 1).
- Produces (`electrum_aionostr.relay`):
  - `PublishResult(url: str, accepted: bool, message: str)` (frozen dataclass)
  - `PublishError(results: Sequence[PublishResult], reason: str = '')`, `.results`; `str()` is human readable
  - `SubscriptionSink` protocol: `on_req_sent(url)`, `on_event(url, event)`, `on_eose(url)`, `on_disconnected(url)` — must not block
  - `Relay(url, *, get_client_session: Callable[[], ClientSession], get_connect_timeout: Callable[[], float], on_state_change: Callable[[], None] = ..., origin='aionostr', auth_private_key=None, ssl_context=None, log=None)` with `.url`, `.connected: asyncio.Event`, `.first_attempt_done: asyncio.Event`, `start()`, `async close()`, `wake()`, `async restart()`, `add_subscription(sub_id, filters, sink)`, `remove_subscription(sub_id)`, `async publish(event: dict, timeout: float) -> PublishResult`
  - class attributes tests shrink: `BACKOFF_BASE_SEC`, `BACKOFF_MAX_SEC`, `WAKE_MIN_INTERVAL_SEC`, `DELAY_INC_MSG_PROCESSING_SLEEP`
  - `loads`, `dumps` stay importable (used by `benchmark.py`)
- Produces (`tests/relay_server.py`): `LocalRelay` (`start()`, `stop()`, `drop_all()`, `send_raw(text)`, `add_event(event_dict)`, `reqs()`, `closes()`, `published_ids()`, `url`, `handshakes`, `connections`, `open_sockets`, switches `refuse`, `ok_mode`, `send_eose`), `make_event(kind=1, content='test', tags=None) -> Event`, `collect(gen, into) -> Task`, `RelayTestCase` (`start_relay()`, `new_pool(**kw)`, `wait_until(pred, timeout=3.0)`).

Note: after this task `get_anything`/`add_event`/`add_events` in `__init__.py` reference `Manager`, which no longer exists until Task 4. Nothing in the test suite calls them in between. This is intentional; do not add a shim.

- [ ] **Step 1: Write the test relay** — create `tests/relay_server.py`:

```python
"""An in-process nostr relay (NIP-01 subset) and a test base class for relay/pool tests."""
import asyncio
import json
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from aiohttp import web, WSMsgType

from electrum_aionostr.event import Event, create_event
from electrum_aionostr.key import PrivateKey
from electrum_aionostr.relay import Relay

if TYPE_CHECKING:
    from electrum_aionostr.pool import RelayPool


def matches(flt: dict, event: dict) -> bool:
    if 'ids' in flt and event['id'] not in flt['ids']:
        return False
    if 'kinds' in flt and event['kind'] not in flt['kinds']:
        return False
    if 'authors' in flt and event['pubkey'] not in flt['authors']:
        return False
    if 'since' in flt and event['created_at'] < flt['since']:
        return False
    for key, values in flt.items():
        if key.startswith('#'):
            if not any(len(tag) > 1 and tag[0] == key[1:] and tag[1] in values for tag in event['tags']):
                return False
    return True


class LocalRelay:
    """
    A relay on 127.0.0.1. Switches:
      refuse:    reject websocket handshakes (the relay looks down)
      ok_mode:   'accept' | 'reject' | 'silent' (never answers EVENTs)
      send_eose: answer REQs with EOSE after the stored events
    """

    def __init__(self):
        self.events = []  # stored events (dicts)
        self.received = []  # every message clients sent us, parsed
        self.handshakes = 0  # websocket upgrade attempts, including refused ones
        self.connections = 0  # accepted websocket connections
        self.refuse = False
        self.ok_mode = 'accept'
        self.send_eose = True
        self.url = None
        self._sockets = {}  # type: dict[web.WebSocketResponse, dict[str, list]]
        self._runner = None

    @property
    def open_sockets(self) -> int:
        return len(self._sockets)

    def reqs(self) -> list:
        return [m for m in self.received if m[0] == 'REQ']

    def closes(self) -> list:
        return [m for m in self.received if m[0] == 'CLOSE']

    def published_ids(self) -> list:
        return [m[1]['id'] for m in self.received if m[0] == 'EVENT']

    async def start(self) -> None:
        app = web.Application()
        app.router.add_get('/', self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, '127.0.0.1', 0)
        await site.start()
        self.url = f'ws://127.0.0.1:{self._runner.addresses[0][1]}'

    async def stop(self) -> None:
        await self.drop_all()
        await self._runner.cleanup()

    async def drop_all(self) -> None:
        for ws in list(self._sockets):
            await ws.close()

    async def send_raw(self, text: str) -> None:
        for ws in list(self._sockets):
            await ws.send_str(text)

    async def add_event(self, event: dict) -> None:
        """Store the event and send it to matching subscriptions, like a client published it."""
        self.events.append(event)
        for ws, subs in list(self._sockets.items()):
            for sub_id, filters in list(subs.items()):
                if any(matches(f, event) for f in filters):
                    await ws.send_json(['EVENT', sub_id, event])

    async def _handle(self, request):
        self.handshakes += 1
        if self.refuse:
            return web.Response(status=503)
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.connections += 1
        subs = self._sockets[ws] = {}
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    message = json.loads(msg.data)
                    self.received.append(message)
                    await self._on_message(ws, subs, message)
        finally:
            self._sockets.pop(ws, None)
        return ws

    async def _on_message(self, ws, subs: dict, message: list) -> None:
        if message[0] == 'REQ':
            sub_id, filters = message[1], message[2:]
            subs[sub_id] = filters
            for event in list(self.events):
                if any(matches(f, event) for f in filters):
                    await ws.send_json(['EVENT', sub_id, event])
            if self.send_eose:
                await ws.send_json(['EOSE', sub_id])
        elif message[0] == 'CLOSE':
            subs.pop(message[1], None)
        elif message[0] == 'EVENT' and self.ok_mode != 'silent':
            event = message[1]
            accepted = self.ok_mode == 'accept'
            await ws.send_json(['OK', event['id'], accepted, '' if accepted else 'blocked: test relay'])
            if accepted:
                await self.add_event(event)


def make_event(kind: int = 1, content: str = 'test', tags=None) -> Event:
    return create_event(PrivateKey(), kind=kind, content=content, tags=tags)


def collect(gen, into: list) -> asyncio.Task:
    """Consume an event generator in the background."""
    async def run():
        async for event in gen:
            into.append(event)
    return asyncio.create_task(run())


class RelayTestCase(unittest.IsolatedAsyncioTestCase):
    """Shrinks the relay supervisor's timings so that reconnect tests are fast."""

    async def asyncSetUp(self):
        fast = dict(BACKOFF_BASE_SEC=0.05, BACKOFF_MAX_SEC=0.2, WAKE_MIN_INTERVAL_SEC=0.0,
                    DELAY_INC_MSG_PROCESSING_SLEEP=0.0)
        for name, value in fast.items():
            patcher = mock.patch.object(Relay, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    async def start_relay(self) -> LocalRelay:
        relay = LocalRelay()
        await relay.start()
        self.addAsyncCleanup(relay.stop)
        return relay

    def new_pool(self, **kwargs) -> 'RelayPool':
        from electrum_aionostr.pool import RelayPool
        kwargs.setdefault('connect_timeout', 2)
        pool = RelayPool(**kwargs)
        self.addAsyncCleanup(pool.close)
        return pool

    async def wait_until(self, predicate, timeout: float = 3.0) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not predicate():
            if loop.time() > deadline:
                self.fail("condition not reached in time")
            await asyncio.sleep(0.01)
```

- [ ] **Step 2: Write the failing tests** — create `tests/test_relay.py`:

```python
import asyncio
import json
from unittest import mock

from aiohttp import ClientSession

from electrum_aionostr.event import Event
from electrum_aionostr.key import PrivateKey
from electrum_aionostr.relay import Relay, PublishResult

from .relay_server import RelayTestCase, make_event


class RecordingSink:
    def __init__(self):
        self.events = []

    def on_req_sent(self, url): pass
    def on_event(self, url, event): self.events.append(event)
    def on_eose(self, url): pass
    def on_disconnected(self, url): pass


class TestRelay(RelayTestCase):

    async def start_client(self, url: str) -> Relay:
        client = ClientSession()
        self.addAsyncCleanup(client.close)
        relay = Relay(url, get_client_session=lambda: client, get_connect_timeout=lambda: 2)
        self.addAsyncCleanup(relay.close)
        relay.start()
        return relay

    async def test_reconnect_resends_only_active_subscriptions(self):
        server = await self.start_relay()
        relay = await self.start_client(server.url)
        active, removed = RecordingSink(), RecordingSink()
        relay.add_subscription('active', [{'kinds': [1]}], active)
        relay.add_subscription('removed', [{'kinds': [2]}], removed)
        await self.wait_until(relay.connected.is_set)
        relay.remove_subscription('removed')
        await self.wait_until(lambda: server.closes())

        await server.drop_all()
        await self.wait_until(lambda: len(server.reqs()) == 3)

        self.assertEqual(['active', 'removed', 'active'], [m[1] for m in server.reqs()])
        event = make_event(kind=1)
        await server.add_event(event.to_json_object())
        await self.wait_until(lambda: active.events)
        self.assertEqual([event.id], [e.id for e in active.events])

    async def test_publish_reports_what_the_relay_answered(self):
        server = await self.start_relay()
        relay = await self.start_client(server.url)
        await self.wait_until(relay.connected.is_set)

        self.assertEqual(PublishResult(relay.url, True, ''), await relay.publish(make_event().to_json_object(), 2))
        server.ok_mode = 'reject'
        result = await relay.publish(make_event().to_json_object(), 2)
        self.assertFalse(result.accepted)
        self.assertIn('blocked', result.message)
        server.ok_mode = 'silent'
        result = await relay.publish(make_event().to_json_object(), 0.2)
        self.assertEqual(PublishResult(relay.url, False, 'timeout'), result)
        # a dropped connection answers pending publishes right away instead of after the timeout
        pending = asyncio.create_task(relay.publish(make_event().to_json_object(), 10))
        await self.wait_until(lambda: len(server.published_ids()) == 4)
        await server.drop_all()
        result = await asyncio.wait_for(pending, 2)
        self.assertEqual(PublishResult(relay.url, False, 'disconnected'), result)

    async def test_bad_messages_are_dropped_without_stalling_the_connection(self):
        server = await self.start_relay()
        relay = await self.start_client(server.url)
        sink = RecordingSink()
        relay.add_subscription('sub', [{'kinds': [1]}], sink)
        await self.wait_until(relay.connected.is_set)

        await server.send_raw('not json')
        await server.send_raw('["EVENT", "sub", {"garbage": true}]')
        # validly signed, but verifying the malformed delegation tag raises
        key = PrivateKey()
        unsigned = Event(pubkey=key.public_key.hex(), kind=1, tags=[['delegation', 'x']])
        sig = Event._sign_event_id(private_key_hex=key.hex(), event_id=unsigned.id)
        await server.send_raw(json.dumps(['EVENT', 'sub', dict(unsigned.to_json_object(), sig=sig)]))
        good = make_event(kind=1)
        await server.add_event(good.to_json_object())

        # used to stall 5 s per bad message
        await self.wait_until(lambda: sink.events, timeout=2)
        self.assertEqual([good.id], [e.id for e in sink.events])

    async def test_restart_replaces_the_connection_and_skips_backoff(self):
        server = await self.start_relay()
        relay = await self.start_client(server.url)
        await self.wait_until(relay.connected.is_set)

        await relay.restart()  # e.g. after a proxy change: the old socket must not stay around
        await self.wait_until(lambda: server.connections == 2 and server.open_sockets == 1)

        with mock.patch.object(Relay, 'BACKOFF_BASE_SEC', 30), mock.patch.object(Relay, 'BACKOFF_MAX_SEC', 30):
            await server.drop_all()
            await self.wait_until(lambda: not relay.connected.is_set())
            await asyncio.sleep(0.05)  # now sleeping in backoff
            await relay.restart()
            await self.wait_until(relay.connected.is_set, timeout=2)
        self.assertEqual(3, server.connections)
```

Why each test exists: re-sending only live subscriptions after a reconnect (a removed one must not come back and occupy a relay slot); publish must report accept/reject/timeout and answer immediately when the socket drops (review F05, F15); one bad message must not stall a connection other consumers share (F01); `restart()` must drop the old socket and skip the backoff (used by `set_proxy`).

- [ ] **Step 3: Run them to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest -q tests/test_relay.py`
Expected: collection error `ImportError: cannot import name 'PublishResult' from 'electrum_aionostr.relay'`.

- [ ] **Step 4: Rewrite `src/electrum_aionostr/relay.py`** with this content:

```python
import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Optional, Callable, Dict, Sequence, Protocol, Tuple, TYPE_CHECKING

from aiohttp import WSMsgType

from .event import Event, create_event
from .key import PrivateKey
from .util import normalize_url

try:
    import orjson
    loads = orjson.loads
    dumps = lambda obj: orjson.dumps(obj).decode()  # orjson.dumps returns bytes
except ImportError:
    import json
    loads = json.loads
    dumps = json.dumps

if TYPE_CHECKING:
    from ssl import SSLContext
    from aiohttp import ClientSession, ClientWebSocketResponse


AUTH_EVENT_KIND = 22242  # NIP-42


@dataclass(frozen=True)
class PublishResult:
    url: str
    accepted: bool
    message: str


class PublishError(Exception):
    """No relay accepted the event. `results` holds what each relay answered."""

    def __init__(self, results: Sequence[PublishResult], reason: str = ''):
        self.results = list(results)
        details = '; '.join(f"{r.url}: {r.message or 'rejected'}" for r in self.results)
        msg = reason or 'event was not accepted by any relay'
        super().__init__(f"{msg} ({details})" if details else msg)


class SubscriptionSink(Protocol):
    """Receives what one relay delivers for one subscription. Implementations must not block."""
    def on_req_sent(self, url: str) -> None: ...
    def on_event(self, url: str, event: Event) -> None: ...
    def on_eose(self, url: str) -> None: ...
    def on_disconnected(self, url: str) -> None: ...


class Relay:
    """
    One websocket connection to a relay. A single supervisor task owns the connection and
    reconnects with backoff; subscriptions are kept and re-sent after every reconnect.
    Created and shared by RelayPool.
    """
    DELAY_INC_MSG_PROCESSING_SLEEP = 0.005  # seconds between messages, mitigates CPU-DoS (sigchecks)
    MAX_MESSAGE_LEN = 64000
    HEARTBEAT_SEC = 30.0  # aiohttp pings; a connection without pong is considered dead
    BACKOFF_BASE_SEC = 1.0
    BACKOFF_MAX_SEC = 300.0
    BACKOFF_RESET_AFTER_SEC = 60.0  # connected at least this long -> backoff starts from scratch
    WAKE_MIN_INTERVAL_SEC = 10.0  # rate limit for skipping a backoff sleep on demand
    CLOSE_TIMEOUT_SEC = 2.0

    def __init__(
        self,
        url: str,
        *,
        get_client_session: Callable[[], 'ClientSession'],
        get_connect_timeout: Callable[[], float],
        on_state_change: Callable[[], None] = lambda: None,
        origin: str = 'aionostr',
        auth_private_key: Optional[str] = None,
        ssl_context: Optional['SSLContext'] = None,
        log: Optional[logging.Logger] = None,
    ):
        self.url = normalize_url(url)
        self.log = log or logging.getLogger(__name__)
        self._get_client_session = get_client_session
        self._get_connect_timeout = get_connect_timeout
        self._on_state_change = on_state_change
        self._origin = origin
        self._auth_private_key = auth_private_key
        self._ssl_context = ssl_context
        self.connected = asyncio.Event()  # set once all subscriptions were (re-)sent
        self.first_attempt_done = asyncio.Event()  # the first connection attempt succeeded or failed
        self._subs = {}  # type: Dict[str, Tuple[Tuple[dict, ...], SubscriptionSink]]
        self._pending_oks = {}  # type: Dict[str, asyncio.Future]
        self._ws = None  # type: Optional[ClientWebSocketResponse]  # set while REQ/CLOSE can be sent
        self._auth_key = None  # type: Optional[PrivateKey]  # random, per websocket
        self._send_lock = asyncio.Lock()
        self._supervisor = None  # type: Optional[asyncio.Task]
        self._tasks = set()  # type: set[asyncio.Task]
        self._closed = False
        self._attempt = 0
        self._in_backoff = False
        self._wake_event = asyncio.Event()
        self._last_wake = float('-inf')

    def start(self) -> None:
        assert self._supervisor is None and not self._closed
        self._supervisor = asyncio.create_task(self._supervise())

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        tasks = [t for t in (self._supervisor, *self._tasks) if t is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def wake(self) -> None:
        """If we are waiting in backoff, try to connect right away (rate-limited)."""
        if not self._in_backoff:
            return
        now = asyncio.get_running_loop().time()
        if now - self._last_wake < self.WAKE_MIN_INTERVAL_SEC:
            return
        self._last_wake = now
        self._wake_event.set()

    async def restart(self) -> None:
        """Abort whatever the supervisor is doing (backoff, connecting, connected) and reconnect now."""
        if self._closed:
            return
        old = self._supervisor
        try:
            if old is not None:
                old.cancel()
                await asyncio.wait({old})
        finally:
            if not self._closed and self._supervisor is old:
                self._attempt = 0
                self._supervisor = asyncio.create_task(self._supervise())

    def add_subscription(self, sub_id: str, filters: Sequence[dict], sink: SubscriptionSink) -> None:
        self._subs[sub_id] = (tuple(filters), sink)
        if (ws := self._ws) is not None:
            self._spawn(self._send_req(sub_id, ws))
        # otherwise the supervisor sends it once connected

    def remove_subscription(self, sub_id: str) -> None:
        if self._subs.pop(sub_id, None) is None:
            return
        if (ws := self._ws) is not None:
            self._spawn(self._send_close(sub_id, ws))

    async def publish(self, event: dict, timeout: float) -> PublishResult:
        """Send the event and wait for the relay's OK."""
        ws = self._ws
        if ws is None or not self.connected.is_set():
            return PublishResult(self.url, False, 'not connected')
        event_id = event['id']
        fut = self._pending_oks.get(event_id)
        if fut is None:  # concurrent publishes of the same event share one OK
            fut = self._pending_oks[event_id] = asyncio.get_running_loop().create_future()
            try:
                await self._send(["EVENT", event], ws=ws)
            except Exception as e:
                if not fut.done():
                    fut.set_result((False, f'send failed: {e!r}'))
        try:
            await asyncio.wait_for(asyncio.shield(fut), timeout)
        except asyncio.TimeoutError:
            if not fut.done():
                fut.set_result((False, 'timeout'))
        finally:
            if fut.done() and self._pending_oks.get(event_id) is fut:
                del self._pending_oks[event_id]
        accepted, message = fut.result()
        return PublishResult(self.url, accepted, message)

    # --- supervisor ---

    async def _supervise(self) -> None:
        loop = asyncio.get_running_loop()
        while not self._closed:
            try:
                ws = await self._connect_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log.debug(f"{self.url}: connection attempt failed: {e!r}")
                self.first_attempt_done.set()
                await self._backoff()
                continue
            connected_at = loop.time()
            try:
                await self._on_open(ws)
                self.first_attempt_done.set()
                await self._receive_loop(ws)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log.debug(f"{self.url}: connection lost: {e!r}")
            finally:
                self.first_attempt_done.set()
                self._on_socket_closed(ws)
                await self._close_ws(ws)
            if loop.time() - connected_at >= self.BACKOFF_RESET_AFTER_SEC:
                self._attempt = 0
            await self._backoff()

    async def _connect_once(self) -> 'ClientWebSocketResponse':
        client = self._get_client_session()
        return await asyncio.wait_for(
            client.ws_connect(
                self.url,
                origin=self._origin,
                ssl=self._ssl_context if self._ssl_context is not None else True,
                heartbeat=self.HEARTBEAT_SEC,
            ),
            timeout=self._get_connect_timeout(),
        )

    async def _on_open(self, ws: 'ClientWebSocketResponse') -> None:
        # One synchronous step: every subscription added from now on sends its own REQ,
        # every earlier one is in the snapshot. Never iterate self._subs across an await.
        self._ws = ws
        self._auth_key = None
        snapshot = list(self._subs.items())
        for sub_id, (filters, sink) in snapshot:
            if sub_id not in self._subs:  # removed while we were replaying
                continue
            await self._send(["REQ", sub_id, *filters], ws=ws)
            sink.on_req_sent(self.url)
        self.connected.set()
        self.log.info(f"connected to {self.url}")
        self._on_state_change()

    def _on_socket_closed(self, ws: 'ClientWebSocketResponse') -> None:
        if self._ws is not ws:
            return
        self._ws = None
        was_connected = self.connected.is_set()
        self.connected.clear()
        for fut in self._pending_oks.values():
            if not fut.done():
                fut.set_result((False, 'disconnected'))
        self._pending_oks.clear()
        for _filters, sink in list(self._subs.values()):
            sink.on_disconnected(self.url)
        if was_connected:
            self.log.info(f"disconnected from {self.url}")
        self._on_state_change()

    async def _close_ws(self, ws: 'ClientWebSocketResponse') -> None:
        try:
            await asyncio.wait_for(ws.close(), self.CLOSE_TIMEOUT_SEC)
        except Exception:
            pass

    async def _backoff(self) -> None:
        self._attempt += 1
        cap = min(self.BACKOFF_MAX_SEC, self.BACKOFF_BASE_SEC * 2 ** min(self._attempt, 16))
        delay = random.uniform(min(self.BACKOFF_BASE_SEC, cap), cap)
        self._wake_event.clear()
        self._in_backoff = True
        try:
            await asyncio.wait_for(self._wake_event.wait(), delay)
        except asyncio.TimeoutError:
            pass
        finally:
            self._in_backoff = False

    async def _receive_loop(self, ws: 'ClientWebSocketResponse') -> None:
        while True:
            msg = await ws.receive()
            if msg.type == WSMsgType.TEXT:
                try:
                    self._handle_message(msg.data)
                except Exception as e:
                    # drop only this message: other consumers share this connection
                    self.log.debug(f"{self.url}: dropping bad message: {e!r}")
            elif msg.type == WSMsgType.BINARY:
                pass
            else:  # CLOSE, CLOSING, CLOSED, ERROR
                return
            await asyncio.sleep(self.DELAY_INC_MSG_PROCESSING_SLEEP)

    def _handle_message(self, data: str) -> None:
        if len(data) > self.MAX_MESSAGE_LEN:
            self.log.debug(f"{self.url}: message too long: {len(data)}")
            return
        message = loads(data)
        if not isinstance(message, list) or not message:
            raise ValueError("message is not a non-empty list")
        msg_type = message[0]
        if msg_type == 'EVENT':
            entry = self._subs.get(message[1])
            if entry is not None:
                # note: Event.from_json does basic validation and the (expensive) sigcheck
                entry[1].on_event(self.url, Event.from_json(message[2]))
        elif msg_type == 'EOSE':
            entry = self._subs.get(message[1])
            if entry is not None:
                entry[1].on_eose(self.url)
        elif msg_type == 'OK':
            self._handle_ok(message)
        elif msg_type == 'AUTH':
            if not isinstance(message[1], str):
                raise ValueError("malformed AUTH")
            self._spawn(self._authenticate(message[1], self._ws))
        elif msg_type == 'NOTICE':
            self.log.debug(f"notice from {self.url}: {str(message[1])[:200]}")
        else:
            self.log.debug(f"unknown message from {self.url}: {data[:200]}")

    def _handle_ok(self, message: list) -> None:
        if len(message) < 3:
            raise ValueError("malformed OK")
        event_id, accepted = message[1], message[2]
        reason = message[3] if len(message) > 3 else ''
        if not (isinstance(event_id, str) and isinstance(accepted, bool) and isinstance(reason, str)):
            raise ValueError("malformed OK")
        fut = self._pending_oks.pop(event_id, None)
        if fut is not None and not fut.done():
            fut.set_result((accepted, reason))

    async def _authenticate(self, challenge: str, ws: Optional['ClientWebSocketResponse']) -> None:
        if ws is None:
            return
        key = self._auth_private_key
        if key is None:
            if self._auth_key is None:
                self._auth_key = PrivateKey()
            key = self._auth_key
        auth_event = create_event(key, kind=AUTH_EVENT_KIND, tags=[['challenge', challenge], ['relay', self.url]])
        await self._send(["AUTH", auth_event.to_json_object()], ws=ws)

    async def _send(self, message: list, *, ws: 'ClientWebSocketResponse') -> None:
        async with self._send_lock:
            if ws is not self._ws or ws.closed:
                raise ConnectionError(f"{self.url}: not connected")
            await ws.send_str(dumps(message))

    async def _send_req(self, sub_id: str, ws: 'ClientWebSocketResponse') -> None:
        entry = self._subs.get(sub_id)
        if entry is None:
            return
        await self._send(["REQ", sub_id, *entry[0]], ws=ws)
        entry[1].on_req_sent(self.url)

    async def _send_close(self, sub_id: str, ws: 'ClientWebSocketResponse') -> None:
        try:
            await asyncio.wait_for(self._send(["CLOSE", sub_id], ws=ws), self.CLOSE_TIMEOUT_SEC)
        except Exception as e:
            self.log.debug(f"{self.url}: could not send CLOSE: {e!r}")

    def _spawn(self, coro) -> None:
        if self._closed:
            coro.close()
            return
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._on_task_done)

    def _on_task_done(self, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        if task.cancelled() or task.exception() is None:
            return
        exc = task.exception()
        if isinstance(exc, ConnectionError):
            self.log.debug(f"{self.url}: {exc!r}")
        else:
            self.log.warning(f"{self.url}: background task failed", exc_info=exc)
```

- [ ] **Step 5: Update the package import and remove the obsolete tests**

In `src/electrum_aionostr/__init__.py` replace the line

```python
from .relay import Manager, Relay
```

with

```python
from .relay import Relay, PublishResult, PublishError
```

then

```bash
git rm tests/test_manager.py
```

- [ ] **Step 6: Run the tests**

Run: `PYTHONPATH=src python3 -m pytest -q tests`
Expected: `12 passed` (test_relay 4, test_event 5, test_key 2, test_aionostr 1). Run it 3 times; it must pass every time.

- [ ] **Step 7: Commit**

```bash
git add src/electrum_aionostr/relay.py src/electrum_aionostr/__init__.py tests/relay_server.py tests/test_relay.py
git commit -m "relay: one supervisor task per relay connection

Reconnects with backoff (wake/restart can skip it), re-sends active
subscriptions after every reconnect, never blocks on consumers, drops
malformed messages without stalling, and reports per-relay publish
results. Adds an in-process test relay. Manager is re-added on top of
the new RelayPool in a later commit."
```

### Task 3: `RelayPool` and `NostrSession`

**Files:**
- Create: `src/electrum_aionostr/pool.py`, `tests/test_pool.py`
- Modify: `src/electrum_aionostr/__init__.py` (one import line)

**Interfaces:**
- Consumes: `Relay`, `PublishResult`, `PublishError`, `SubscriptionSink` (Task 2); `normalize_url`, `is_valid_relay_url` (Task 1).
- Produces (`electrum_aionostr.pool`, all exported from the package):
  - `RelayPool(*, origin='aionostr', log=None, ssl_context=None, proxy: ProxyConnector | None = None, connect_timeout: float = 5.0, linger_sec: float = 180.0, auth_private_key: str | None = None)`; attribute `connect_timeout`; `set_default_relays(urls)` (sync); `open_session(*, name='', use_default_relays=True, extra_relays=()) -> NostrSession` (sync, on the loop); `async set_proxy(proxy, *, connect_timeout)`; `async close()`; async context manager.
  - `NostrSession`: `.name`, `.relays -> frozenset[str]` (normalized URLs), `connected_relays() -> list[str]` (sorted), `async wait_connected(timeout=None) -> bool`, `async set_extra_relays(urls)`, `get_events(*filters, only_stored=True, single_event=False, filter_future_events_sec=3600)` (async generator), `async publish(event: Event | dict, *, relays=None, timeout=None) -> PublishResult`, `async close()`; class attribute `EOSE_TIMEOUT_SEC = 60`.
  - `RelayInfo(url, connected)`, `PoolClosed`, `SessionClosed`. Internal (used by tests): `_Subscription.MAX_QUEUED_EVENTS`.

- [ ] **Step 1: Write the failing tests** — create `tests/test_pool.py`:

```python
import asyncio
from unittest import mock

from electrum_aionostr.pool import NostrSession, PoolClosed, _Subscription
from electrum_aionostr.relay import Relay, PublishError

from .relay_server import RelayTestCase, make_event, collect


class TestRelayPool(RelayTestCase):

    async def test_sessions_share_one_connection_per_relay(self):
        server = await self.start_relay()
        pool = self.new_pool()
        first = pool.open_session(use_default_relays=False, extra_relays=[server.url])
        second = pool.open_session(use_default_relays=False, extra_relays=[server.url.upper() + '/'])
        got_first, got_second = [], []
        collect(first.get_events({'kinds': [1]}, only_stored=False), got_first)
        collect(second.get_events({'kinds': [2]}, only_stored=False), got_second)
        await self.wait_until(lambda: len(server.reqs()) == 2)

        kind1, kind2 = make_event(kind=1), make_event(kind=2)
        await server.add_event(kind1.to_json_object())
        await server.add_event(kind2.to_json_object())
        await self.wait_until(lambda: got_first and got_second)

        self.assertEqual([kind1.id], [e.id for e in got_first])
        self.assertEqual([kind2.id], [e.id for e in got_second])
        self.assertEqual(1, server.connections)

    async def test_session_only_uses_its_own_relays(self):
        mine, other = await self.start_relay(), await self.start_relay()
        pool = self.new_pool()
        session = pool.open_session(use_default_relays=False, extra_relays=[mine.url])
        other_session = pool.open_session(use_default_relays=False, extra_relays=[other.url])
        self.assertTrue(await other_session.wait_connected(2))

        collect(session.get_events({'kinds': [7]}, only_stored=False), [])
        await self.wait_until(lambda: mine.reqs())
        event = make_event(kind=7)
        await session.publish(event)

        self.assertIn(event.id, mine.published_ids())
        self.assertEqual([], other.reqs())
        self.assertEqual([], other.published_ids())

    async def test_unused_relay_lingers_then_closes(self):
        server = await self.start_relay()
        pool = self.new_pool(linger_sec=0.5)
        session = pool.open_session(use_default_relays=False, extra_relays=[server.url])
        self.assertTrue(await session.wait_connected(2))
        await session.close()

        session = pool.open_session(use_default_relays=False, extra_relays=[server.url])
        self.assertTrue(await session.wait_connected(0.1))  # still connected, reused
        self.assertEqual(1, server.connections)
        await session.close()
        await self.wait_until(lambda: server.open_sockets == 0)

        session = pool.open_session(use_default_relays=False, extra_relays=[server.url])
        self.assertTrue(await session.wait_connected(2))  # a fresh relay, not the closed one
        self.assertEqual(2, server.connections)

    async def test_relay_that_was_down_is_woken_when_needed_and_keeps_subscriptions(self):
        server = await self.start_relay()
        server.refuse = True
        with mock.patch.object(Relay, 'BACKOFF_BASE_SEC', 30), mock.patch.object(Relay, 'BACKOFF_MAX_SEC', 30):
            pool = self.new_pool()
            listener = pool.open_session(use_default_relays=False, extra_relays=[server.url])
            got = []
            collect(listener.get_events({'kinds': [1]}, only_stored=False), got)
            await self.wait_until(lambda: server.handshakes == 1)
            await asyncio.sleep(0.05)  # now sleeping in backoff

            server.refuse = False
            newcomer = pool.open_session(use_default_relays=False, extra_relays=[server.url])
            self.assertTrue(await newcomer.wait_connected(2))  # without waking: 30 s

            event = make_event(kind=1)
            await server.add_event(event.to_json_object())
            await self.wait_until(lambda: got)
            self.assertEqual([event.id], [e.id for e in got])

    async def test_consumer_that_stops_reading_does_not_block_others(self):
        server = await self.start_relay()
        pool = self.new_pool()
        session = pool.open_session(use_default_relays=False, extra_relays=[server.url])

        async def read_one_then_stall():  # like psbt_nostr waiting for the user
            async for _event in session.get_events({'kinds': [1]}, only_stored=False):
                await asyncio.Event().wait()

        with mock.patch.object(_Subscription, 'MAX_QUEUED_EVENTS', 5):
            asyncio.create_task(read_one_then_stall())
            got = []
            collect(session.get_events({'kinds': [2]}, only_stored=False), got)
            await self.wait_until(lambda: len(server.reqs()) == 2)
            for _ in range(20):
                await server.add_event(make_event(kind=1).to_json_object())
            wanted = make_event(kind=2)
            await server.add_event(wanted.to_json_object())
            await self.wait_until(lambda: got)
        self.assertEqual([wanted.id], [e.id for e in got])

    async def test_publish_results(self):
        accepting, rejecting = await self.start_relay(), await self.start_relay()
        rejecting.ok_mode = 'reject'
        pool = self.new_pool()
        both = pool.open_session(use_default_relays=False, extra_relays=[accepting.url, rejecting.url])
        await self.wait_until(lambda: len(both.connected_relays()) == 2)
        result = await both.publish(make_event())
        self.assertEqual(accepting.url, result.url)

        only_rejecting = pool.open_session(use_default_relays=False, extra_relays=[rejecting.url])
        with self.assertRaises(PublishError) as ctx:
            await only_rejecting.publish(make_event())
        self.assertIn('blocked', str(ctx.exception))
        rejecting.ok_mode = 'silent'
        with self.assertRaises(PublishError):
            await only_rejecting.publish(make_event(), timeout=0.3)

        no_relays = pool.open_session(use_default_relays=False)
        with self.assertRaises(PublishError):
            await asyncio.wait_for(no_relays.publish(make_event(), timeout=10), 1)  # fails right away

    async def test_publish_also_reaches_relays_that_connect_later(self):
        fast, late = await self.start_relay(), await self.start_relay()
        late.refuse = True
        pool = self.new_pool()
        session = pool.open_session(use_default_relays=False, extra_relays=[fast.url, late.url])
        await self.wait_until(lambda: session.connected_relays() == [fast.url])

        event = make_event()
        result = await session.publish(event, timeout=3)
        self.assertEqual(fast.url, result.url)
        late.refuse = False
        await self.wait_until(lambda: event.id in late.published_ids())

    async def test_stored_query_does_not_wait_for_down_or_silent_relays(self):
        stored = make_event(kind=1)
        up, down, silent = await self.start_relay(), await self.start_relay(), await self.start_relay()
        down.refuse = True
        silent.send_eose = False
        for relay in (up, silent):
            await relay.add_event(stored.to_json_object())
        pool = self.new_pool()

        session = pool.open_session(use_default_relays=False, extra_relays=[up.url, down.url])
        await self.wait_until(lambda: session.connected_relays() == [up.url])
        events = [e async for e in session.get_events({'kinds': [1]})]
        self.assertEqual([stored.id], [e.id for e in events])
        await self.wait_until(lambda: up.closes())  # a finished query does not stay subscribed

        with mock.patch.object(NostrSession, 'EOSE_TIMEOUT_SEC', 0.5):
            session = pool.open_session(use_default_relays=False, extra_relays=[up.url, silent.url])
            await self.wait_until(lambda: len(session.connected_relays()) == 2)
            events = await asyncio.wait_for(self.drain(session.get_events({'kinds': [1]})), 2)
        self.assertEqual([stored.id], [e.id for e in events])  # once, although both relays sent it

    async def test_relay_changes_and_proxy_switch_keep_subscriptions(self):
        first, second = await self.start_relay(), await self.start_relay()
        pool = self.new_pool()
        pool.set_default_relays([first.url])
        session = pool.open_session()  # follows the default relays
        got = []
        collect(session.get_events({'kinds': [1]}, only_stored=False), got)
        await self.wait_until(lambda: first.reqs())

        pool.set_default_relays([second.url])
        await self.wait_until(lambda: second.reqs() and first.closes())
        await session.set_extra_relays(['not a relay url', 'http://example.com', first.url])
        self.assertEqual({first.url, second.url}, session.relays)
        await self.wait_until(lambda: len(session.connected_relays()) == 2)

        await pool.set_proxy(None, connect_timeout=2)
        await self.wait_until(lambda: first.connections == 2 and second.connections == 2)
        event = make_event(kind=1)
        await second.add_event(event.to_json_object())
        await self.wait_until(lambda: got)
        self.assertEqual([event.id], [e.id for e in got])

    async def test_close_releases_waiting_consumers_and_stops_everything(self):
        server = await self.start_relay()
        pool = self.new_pool()
        session = pool.open_session(use_default_relays=False, extra_relays=[server.url])
        consumer = asyncio.create_task(self.drain(session.get_events({'kinds': [1]}, only_stored=False)))
        await self.wait_until(lambda: server.reqs())

        await pool.close()

        self.assertEqual([], await asyncio.wait_for(consumer, 1))  # returned normally
        await self.wait_until(lambda: server.open_sockets == 0)
        ours = [t for t in asyncio.all_tasks()
                if t.get_coro().__qualname__.split('.')[0] in ('Relay', 'RelayPool', 'NostrSession')]
        self.assertEqual([], ours)
        with self.assertRaises(PoolClosed):
            await session.publish(make_event())

    @staticmethod
    async def drain(gen) -> list:
        return [event async for event in gen]
```

Why each test exists (spec §7): one socket per relay across sessions and URL spellings; sessions never leak REQs/EVENTs to other sessions' relays; linger reuse and the fresh-relay-after-expiry race; a relay stuck in backoff is woken when a session needs it; a consumer that stops reading (psbt_nostr) cannot block others; publish results incl. empty relay set; publish reaches relays that connect after the first acceptance; stored queries neither wait for down relays nor hang on relays withholding EOSE, and de-duplicate across relays; default/extra relay changes and `set_proxy` keep subscriptions; `close()` releases blocked consumers and leaves nothing running.

- [ ] **Step 2: Run them to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest -q tests/test_pool.py`
Expected: collection error `ModuleNotFoundError: No module named 'electrum_aionostr.pool'`.

- [ ] **Step 3: Create `src/electrum_aionostr/pool.py`**:

```python
import asyncio
import logging
import secrets
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Optional, Iterable, Union, AsyncGenerator, Dict, Set, TYPE_CHECKING

from aiohttp import ClientSession

from .event import Event
from .relay import Relay, PublishResult, PublishError
from .util import normalize_url, is_valid_relay_url

if TYPE_CHECKING:
    from ssl import SSLContext
    from aiohttp_socks import ProxyConnector


class PoolClosed(Exception):
    pass


class SessionClosed(Exception):
    pass


@dataclass(frozen=True)
class RelayInfo:
    url: str
    connected: bool


class _Subscription:
    """One get_events() call. Implements relay.SubscriptionSink and never blocks the relay."""
    MAX_QUEUED_EVENTS = 1000
    MAX_SEEN_IDS = 10_000

    def __init__(self, *, filters: tuple, only_stored: bool, log: logging.Logger):
        self.sub_id = secrets.token_hex(8)
        self.filters = filters
        self.only_stored = only_stored
        self.log = log
        self._events = deque()  # type: deque[Event]
        self._seen = OrderedDict()  # type: OrderedDict[str, None]  # LRU of delivered event ids
        self._pending_eose = set()  # type: Set[str]  # relays we sent the REQ to and wait on
        self._got_req = False
        self._stored_done = False
        self._closed = False
        self._wakeup = asyncio.Event()
        self._dropped = 0

    def on_req_sent(self, url: str) -> None:
        if self.only_stored and not self._stored_done:
            self._got_req = True
            self._pending_eose.add(url)

    def on_event(self, url: str, event: Event) -> None:
        if event.id in self._seen:
            self._seen.move_to_end(event.id)
            return
        if len(self._events) >= self.MAX_QUEUED_EVENTS:
            self._dropped += 1
            if self._dropped % 100 == 1:
                self.log.warning(f"subscription {self.sub_id}: consumer too slow, dropped {self._dropped} events")
            return
        self._seen[event.id] = None
        if len(self._seen) > self.MAX_SEEN_IDS:
            self._seen.popitem(last=False)
        self._events.append(event)
        self._wakeup.set()

    def on_eose(self, url: str) -> None:
        self._relay_done(url)

    def on_disconnected(self, url: str) -> None:
        self._relay_done(url)

    def relay_removed(self, url: str) -> None:
        self._relay_done(url)

    def _relay_done(self, url: str) -> None:
        self._pending_eose.discard(url)
        if self.only_stored and self._got_req and not self._pending_eose and not self._stored_done:
            self._stored_done = True
            self._wakeup.set()

    def close(self) -> None:
        self._closed = True
        self._wakeup.set()

    async def next_event(self, inactivity_timeout: Optional[float]) -> Optional[Event]:
        """The next event, or None once the subscription is finished."""
        while True:
            if self._events:
                return self._events.popleft()
            if self._closed or self._stored_done:
                return None
            self._wakeup.clear()
            try:
                await asyncio.wait_for(self._wakeup.wait(), inactivity_timeout)
            except asyncio.TimeoutError:
                return None


class NostrSession:
    """A consumer's handle on the pool: its own relay set, subscriptions and publishing."""
    EOSE_TIMEOUT_SEC = 60  # only_stored queries end after this long without any progress

    def __init__(self, pool: 'RelayPool', *, name: str, use_default_relays: bool, extra_relays: Iterable[str]):
        self.name = name
        self._pool = pool
        self._use_default_relays = use_default_relays
        self._extra_relays = pool._valid_urls(extra_relays)
        self._relays = frozenset()  # type: frozenset[str]
        self._subs = {}  # type: Dict[str, _Subscription]
        self._closed = False

    @property
    def relays(self) -> frozenset:
        return self._relays

    def connected_relays(self) -> list:
        return sorted(url for url in self._relays if self._pool._is_connected(url))

    async def wait_connected(self, timeout: Optional[float] = None) -> bool:
        """Wait until any relay of this session is connected. False on timeout."""
        self._check_open()
        self._pool._wake(self._relays)
        loop = asyncio.get_running_loop()
        deadline = None if timeout is None else loop.time() + timeout
        while True:
            changed = self._pool._state_changed
            self._check_open()
            if self.connected_relays():
                return True
            remaining = None if deadline is None else deadline - loop.time()
            if remaining is not None and remaining <= 0:
                return False
            try:
                await asyncio.wait_for(changed.wait(), remaining)
            except asyncio.TimeoutError:
                return False

    async def set_extra_relays(self, urls: Iterable[str]) -> None:
        self._check_open()
        self._extra_relays = self._pool._valid_urls(urls)
        self._pool._update_session_relays(self)

    async def get_events(
        self,
        *filters: dict,
        only_stored: bool = True,
        single_event: bool = False,
        filter_future_events_sec: Optional[int] = 3600,
    ) -> AsyncGenerator[Event, None]:
        """
        Request events matching *filters (NIP-01 filters) from this session's relays.
        only_stored: finish once the relays sent all events they currently have (EOSE),
                     instead of waiting for new ones.
        """
        self._check_open()
        sub = _Subscription(filters=filters, only_stored=only_stored, log=self._pool.log)
        self._subs[sub.sub_id] = sub
        for url in self._relays:
            self._pool._relays[url].add_subscription(sub.sub_id, sub.filters, sub)
        self._pool._wake(self._relays)
        try:
            while True:
                event = await sub.next_event(self.EOSE_TIMEOUT_SEC if only_stored else None)
                if event is None:
                    return
                if filter_future_events_sec is not None and event.created_at > time.time() + filter_future_events_sec:
                    self._pool.log.debug(f"event {event.id} too far into future")
                    continue
                yield event
                if single_event:
                    return
        finally:
            # no await in here: this also runs when the generator gets garbage collected
            self._remove_subscription(sub)

    async def publish(
        self,
        event: Union[Event, dict],
        *,
        relays: Optional[Iterable[str]] = None,
        timeout: Optional[float] = None,
    ) -> PublishResult:
        """
        Publish to all relays of this session (or the given subset of them), including relays
        that connect before the deadline. Returns once the first relay accepted the event.
        Raises PublishError if none did within `timeout` (default: the pool's connect_timeout).
        """
        self._check_open()
        event_json = event.to_json_object() if isinstance(event, Event) else dict(event)
        if relays is None:
            targets = set(self._relays)
        else:
            targets = {normalize_url(url) for url in relays}
            if not targets <= self._relays:
                raise ValueError(f"not relays of this session: {sorted(targets - self._relays)}")
        if not targets:
            raise PublishError([], 'no relays to publish to')
        if timeout is None:
            timeout = self._pool.connect_timeout
        return await self._pool._publish(event_json, targets, timeout)

    async def close(self) -> None:
        self._close()

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for sub in list(self._subs.values()):
            self._remove_subscription(sub)
            sub.close()  # wakes the consumer, its get_events() returns
        self._pool._forget_session(self)

    def _remove_subscription(self, sub: _Subscription) -> None:
        if self._subs.pop(sub.sub_id, None) is None:
            return
        for url in self._relays:
            if (relay := self._pool._relays.get(url)) is not None:
                relay.remove_subscription(sub.sub_id)

    def _wanted_relays(self) -> frozenset:
        if self._closed:
            return frozenset()
        if self._use_default_relays:
            return self._pool._default_relays | self._extra_relays
        return self._extra_relays

    def _check_open(self) -> None:
        if self._pool._closed:
            raise PoolClosed()
        if self._closed:
            raise SessionClosed(self.name)


class RelayPool:
    """
    Shares one connection per relay between all sessions of a process.
    Relays no session uses any more are closed after `linger_sec`.
    """

    def __init__(
        self,
        *,
        origin: str = 'aionostr',
        log: Optional[logging.Logger] = None,
        ssl_context: Optional['SSLContext'] = None,
        proxy: Optional['ProxyConnector'] = None,
        connect_timeout: float = 5.0,
        linger_sec: float = 180.0,
        auth_private_key: Optional[str] = None,
    ):
        self.log = log or logging.getLogger(__name__)
        self.connect_timeout = connect_timeout
        self.linger_sec = linger_sec
        self._origin = origin
        self._ssl_context = ssl_context
        self._proxy = proxy
        self._auth_private_key = auth_private_key
        self._client = None  # type: Optional[ClientSession]
        self._relays = {}  # type: Dict[str, Relay]
        self._users = {}  # type: Dict[str, Set[NostrSession]]
        self._linger_timers = {}  # type: Dict[str, asyncio.TimerHandle]
        self._sessions = set()  # type: Set[NostrSession]
        self._default_relays = frozenset()  # type: frozenset[str]
        self._proxy_lock = asyncio.Lock()
        self._state_changed = asyncio.Event()  # replaced by a new Event on every change
        self._tasks = set()  # type: Set[asyncio.Task]
        self._closed = False

    async def __aenter__(self) -> 'RelayPool':
        return self

    async def __aexit__(self, ex_type, ex, tb) -> None:
        await self.close()

    def set_default_relays(self, urls: Iterable[str]) -> None:
        self._check_open()
        self._default_relays = self._valid_urls(urls)
        for session in list(self._sessions):
            if session._use_default_relays:
                self._update_session_relays(session)

    def open_session(
        self,
        *,
        name: str = '',
        use_default_relays: bool = True,
        extra_relays: Iterable[str] = (),
    ) -> NostrSession:
        self._check_open()
        session = NostrSession(self, name=name, use_default_relays=use_default_relays, extra_relays=extra_relays)
        self._sessions.add(session)
        self._update_session_relays(session)
        return session

    async def set_proxy(self, proxy: Optional['ProxyConnector'], *, connect_timeout: float) -> None:
        """Reconnect every relay through `proxy` (None: direct). Subscriptions are kept."""
        self._check_open()
        async with self._proxy_lock:
            old_client, old_proxy = self._client, self._proxy
            self._client = None  # the next connection attempt creates one with the new proxy
            self._proxy = proxy
            self.connect_timeout = connect_timeout
            await asyncio.gather(*(relay.restart() for relay in list(self._relays.values())))
            await self._close_client(old_client, old_proxy)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for session in list(self._sessions):
            session._close()
        for handle in self._linger_timers.values():
            handle.cancel()
        self._linger_timers.clear()
        relays = list(self._relays.values())
        self._relays.clear()
        await asyncio.gather(*(relay.close() for relay in relays))
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._close_client(self._client, self._proxy)
        self._client = self._proxy = None
        self._notify_state_change()

    # --- internals, used by NostrSession ---

    def _get_client_session(self) -> ClientSession:
        if self._client is None:
            if self._proxy is not None:
                self._client = ClientSession(connector=self._proxy, connector_owner=True)
            else:
                self._client = ClientSession()
        return self._client

    @staticmethod
    async def _close_client(client: Optional[ClientSession], proxy: Optional['ProxyConnector']) -> None:
        if client is not None:
            await client.close()  # also closes the proxy connector it owns
        elif proxy is not None:
            await proxy.close()

    def _update_session_relays(self, session: NostrSession) -> None:
        # synchronous: subscriptions must not change while we iterate them
        old, new = session._relays, session._wanted_relays()
        for url in new - old:
            relay = self._acquire(url, session)
            for sub in session._subs.values():
                relay.add_subscription(sub.sub_id, sub.filters, sub)
        for url in old - new:
            relay = self._relays.get(url)
            for sub in session._subs.values():
                if relay is not None:
                    relay.remove_subscription(sub.sub_id)
                sub.relay_removed(url)
            self._release(url, session)
        session._relays = new
        self._notify_state_change()

    def _forget_session(self, session: NostrSession) -> None:
        for url in session._relays:
            self._release(url, session)
        session._relays = frozenset()
        self._sessions.discard(session)
        self._notify_state_change()

    def _acquire(self, url: str, session: NostrSession) -> Relay:
        if (handle := self._linger_timers.pop(url, None)) is not None:
            handle.cancel()
        relay = self._relays.get(url)
        if relay is None:
            relay = Relay(
                url,
                get_client_session=self._get_client_session,
                get_connect_timeout=lambda: self.connect_timeout,
                on_state_change=self._notify_state_change,
                origin=self._origin,
                auth_private_key=self._auth_private_key,
                ssl_context=self._ssl_context,
                log=self.log,
            )
            self._relays[url] = relay
            relay.start()
        else:
            relay.wake()
        self._users.setdefault(url, set()).add(session)
        return relay

    def _release(self, url: str, session: NostrSession) -> None:
        users = self._users.get(url)
        if users is not None:
            users.discard(session)
            if users:
                return
            del self._users[url]
        if self._closed or url not in self._relays:
            return
        if (handle := self._linger_timers.pop(url, None)) is not None:
            handle.cancel()
        if self.linger_sec <= 0:
            self._expire(url)
        else:
            self._linger_timers[url] = asyncio.get_running_loop().call_later(self.linger_sec, self._expire, url)

    def _expire(self, url: str) -> None:
        self._linger_timers.pop(url, None)
        if self._users.get(url):
            return
        # remove it synchronously, so that a session acquiring this url from now on gets a new relay
        relay = self._relays.pop(url, None)
        if relay is not None:
            self._spawn(relay.close())

    async def _publish(self, event_json: dict, targets: Set[str], timeout: float) -> PublishResult:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        first_accepted = loop.create_future()
        results = []

        async def publish_to(relay: Relay) -> None:
            result = None
            if not relay.connected.is_set():
                try:
                    await asyncio.wait_for(relay.connected.wait(), max(0.0, deadline - loop.time()))
                except asyncio.TimeoutError:
                    result = PublishResult(relay.url, False, 'not connected')
            if result is None:
                result = await relay.publish(event_json, timeout=max(0.0, deadline - loop.time()))
            results.append(result)
            if result.accepted and not first_accepted.done():
                first_accepted.set_result(result)

        tasks = []
        for url in targets:
            relay = self._relays[url]
            relay.wake()
            tasks.append(self._spawn(publish_to(relay)))  # pool-owned: late relays still get it
        all_done = asyncio.ensure_future(asyncio.wait(tasks))
        try:
            await asyncio.wait({first_accepted, all_done}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            all_done.cancel()  # does not cancel the publish tasks themselves
        if first_accepted.done():
            return first_accepted.result()
        raise PublishError(results)

    def _is_connected(self, url: str) -> bool:
        relay = self._relays.get(url)
        return relay is not None and relay.connected.is_set()

    def _wake(self, urls: Iterable[str]) -> None:
        for url in urls:
            if (relay := self._relays.get(url)) is not None:
                relay.wake()

    def _notify_state_change(self) -> None:
        event, self._state_changed = self._state_changed, asyncio.Event()
        event.set()

    def _valid_urls(self, urls: Iterable[str]) -> frozenset:
        valid = set()
        for url in urls:
            if not is_valid_relay_url(url):
                self.log.info(f"ignoring invalid relay url: {url!r:.100}")
                continue
            valid.add(normalize_url(url))
        return frozenset(valid)

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._on_task_done)
        return task

    def _on_task_done(self, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            self.log.warning("background task failed", exc_info=task.exception())

    def _check_open(self) -> None:
        if self._closed:
            raise PoolClosed()
```

- [ ] **Step 4: Export it** — in `src/electrum_aionostr/__init__.py` add below the `from .relay import ...` line:

```python
from .pool import RelayPool, NostrSession, RelayInfo, PoolClosed, SessionClosed
```

- [ ] **Step 5: Run the tests**

Run: `PYTHONPATH=src python3 -m pytest -q tests`
Expected: `22 passed`. Run it 3 times; it must pass every time (the suite takes ~3 s).

- [ ] **Step 6: Commit**

```bash
git add src/electrum_aionostr/pool.py src/electrum_aionostr/__init__.py tests/test_pool.py
git commit -m "pool: add RelayPool and NostrSession

One connection per relay, shared by all sessions of a process. Each
session has its own relay set (default relays plus extras), its own
subscriptions and publishes only to its relays. Unused relays linger
before they are closed, and set_proxy reconnects everything while
keeping subscriptions."
```

### Task 4: `Manager` wrapper, CLI fixes, release prep

**Files:**
- Modify: `src/electrum_aionostr/pool.py` (append), `src/electrum_aionostr/__init__.py`, `src/electrum_aionostr/cli.py`, `src/electrum_aionostr/benchmark.py`, `pyproject.toml`, `docs/history.md`, `README.md`
- Create: `tests/test_manager.py`

**Interfaces:**
- Consumes: `RelayPool`, `NostrSession`, `RelayInfo` (Task 3), `create_event` (Task 1).
- Produces: `Manager(relays=None, origin='aionostr', private_key=None, log=None, ssl_context=None, proxy=None, connect_timeout=None)` with `relays -> list[RelayInfo]` (available before `connect()`), `connected`, `async connect()` (returns once every relay connected or failed its first attempt, bounded by connect_timeout), `async close()`, `get_events(...)`, `async add_event(event: Event | dict) -> str` (event id; raises `PublishError`), `async update_relays(urls)`, async context manager; `NotInitialized`. Package exports `create_event`, `Event`, `Manager`, `NotInitialized`, `__version__ == '0.2.0'`.

- [ ] **Step 1: Write the failing tests** — create `tests/test_manager.py`:

```python
from electrum_aionostr import Manager, get_anything, add_event
from electrum_aionostr.key import PrivateKey

from .relay_server import RelayTestCase, make_event


class TestManager(RelayTestCase):

    async def test_manager_deduplicates_relays(self):
        manager = Manager(['wss://relay.example', 'wss://relay.example/', 'WSS://RELAY.EXAMPLE'])
        self.assertEqual(['wss://relay.example'], [relay.url for relay in manager.relays])
        await manager.close()

    async def test_query_and_publish_through_the_module_helpers(self):
        server = await self.start_relay()
        stored = make_event(kind=1)
        await server.add_event(stored.to_json_object())

        events = await get_anything({'kinds': [1]}, relays=[server.url])
        self.assertEqual([stored.id], [e.id for e in events])

        event_id = await add_event([server.url], private_key=PrivateKey().hex(), kind=1, content='hi')
        self.assertIn(event_id, server.published_ids())
```

- [ ] **Step 2: Run them to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest -q tests/test_manager.py`
Expected: collection error `ImportError: cannot import name 'Manager' from 'electrum_aionostr'`.

- [ ] **Step 3: Append the wrapper to `src/electrum_aionostr/pool.py`** (after the `RelayPool` class, separated by two blank lines):

```python
class NotInitialized(Exception):
    pass


class Manager:
    """
    Compatibility wrapper around a private RelayPool with a single session: the relays given
    here, no default relays, and connections closed as soon as they are not used any more.
    """

    def __init__(
        self,
        relays: Optional[Iterable[str]] = None,
        origin: Optional[str] = 'aionostr',
        private_key: Optional[str] = None,
        log: Optional[logging.Logger] = None,
        ssl_context: Optional['SSLContext'] = None,
        proxy: Optional['ProxyConnector'] = None,
        connect_timeout: Optional[float] = None,
    ):
        self.log = log or logging.getLogger(__name__)
        self._pool = RelayPool(
            origin=origin or 'aionostr',
            log=self.log,
            ssl_context=ssl_context,
            proxy=proxy,
            connect_timeout=connect_timeout or (10 if proxy else 5),
            linger_sec=0,
            auth_private_key=private_key or None,
        )
        self._relay_urls = sorted(self._pool._valid_urls(relays or []))
        self._session = None  # type: Optional[NostrSession]
        self._connect_lock = asyncio.Lock()
        self.connected = False

    @property
    def relays(self) -> list:
        urls = sorted(self._session.relays) if self._session is not None else self._relay_urls
        return [RelayInfo(url, self._pool._is_connected(url)) for url in urls]

    async def connect(self) -> None:
        """Returns once every relay connected or failed its first attempt (bounded by connect_timeout)."""
        async with self._connect_lock:
            if self.connected:
                return
            self._session = self._pool.open_session(name='manager', use_default_relays=False, extra_relays=self._relay_urls)
            waiters = [asyncio.ensure_future(self._pool._relays[url].first_attempt_done.wait())
                       for url in self._session.relays]
            if waiters:
                _done, pending = await asyncio.wait(waiters, timeout=self._pool.connect_timeout)
                for waiter in pending:
                    waiter.cancel()
            self.connected = True
            self.log.info("Connected to %d out of %d relays", len(self._session.connected_relays()), len(waiters))

    async def close(self) -> None:
        await self._pool.close()
        self.connected = False

    async def __aenter__(self) -> 'Manager':
        await self.connect()
        return self

    async def __aexit__(self, ex_type, ex, tb) -> None:
        await self.close()

    async def get_events(
        self,
        *filters: dict,
        only_stored: bool = True,
        single_event: bool = False,
        filter_future_events_sec: Optional[int] = 3600,
    ) -> AsyncGenerator[Event, None]:
        await self.connect()
        async for event in self._session.get_events(
                *filters, only_stored=only_stored, single_event=single_event,
                filter_future_events_sec=filter_future_events_sec):
            yield event

    async def add_event(self, event: Union[Event, dict]) -> str:
        """Publish the event, returns its id. Raises PublishError if no relay accepted it."""
        await self.connect()
        await self._session.publish(event)
        return event.id if isinstance(event, Event) else event['id']

    async def update_relays(self, relays: Iterable[str]) -> None:
        if not self.connected:
            raise NotInitialized("Manager is not connected")
        await self._session.set_extra_relays(relays)
```

- [ ] **Step 4: Update `src/electrum_aionostr/__init__.py`**

Replace everything from the `__version__` line down to (including) the `from .pool import ...` line with:

```python
__version__ = '0.2.0'

import time
from typing import Optional, List, Any

from .event import Event, create_event
from .relay import Relay, PublishResult, PublishError
from .pool import RelayPool, NostrSession, Manager, RelayInfo, PoolClosed, SessionClosed, NotInitialized
```

Replace the whole `_add_event` function (up to, not including, `async def add_event(`) with:

```python
async def _add_event(manager, event:dict=None, private_key='', kind=1, pubkey='', content='', created_at=None, tags=None, direct_message=''):
    """
    Add an event to the network, using the given relays
    event can be specified (as a dict)
    or will be created from the passed in parameters
    """
    if not event:
        from .key import PrivateKey
        from .util import from_nip19
        if not private_key:
            raise Exception("Missing private key")
        if private_key.startswith('nsec'):
            private_key = from_nip19(private_key)['object'].hex()
        prikey = PrivateKey(bytes.fromhex(private_key))
        tags = list(tags or [])
        if direct_message:
            dm_pubkey = from_nip19(direct_message)['object'].hex() if direct_message.startswith('npub') else direct_message
            tags.append(['p', dm_pubkey])
            kind = 4
            content = prikey.encrypt_message(content, dm_pubkey)
        event = create_event(prikey, kind=kind, content=content, tags=tags, created_at=created_at)
    return await manager.add_event(event)
```

- [ ] **Step 5: CLI, benchmark, dependencies** — apply:

```diff
--- a/src/electrum_aionostr/cli.py
+++ b/src/electrum_aionostr/cli.py
@@ -198,7 +198,7 @@
         count = 0
         while True:
             event = await result_queue.get()
-            await man.add_event(event, check_response=True)
+            await man.add_event(event)
             count += 1
             if verbose:
                 click.echo(f'{event.id} from {event.pubkey}')
```

```diff
--- a/src/electrum_aionostr/benchmark.py
+++ b/src/electrum_aionostr/benchmark.py
@@ -18,7 +18,8 @@
 
 from .event import Event
 from .key import PrivateKey
-from .relay import Relay, loads, dumps
+from .pool import RelayPool
+from .relay import dumps
 
 
 class catchtime:
@@ -56,13 +57,14 @@
 
 async def adds_per_second(url, num_events=100):
     events = make_events(num_events)
-    async with ClientSession() as client:
-        relay = Relay(url, client=client)
-        async with relay:
-            with catchtime() as timer:
-                for e in events:
-                    await relay.add_event(e, check_response=True)
-                    timer += 1
+    async with RelayPool(linger_sec=0) as pool:
+        session = pool.open_session(use_default_relays=False, extra_relays=[url])
+        if not await session.wait_connected(timeout=10):
+            raise Exception(f"could not connect to {url}")
+        with catchtime() as timer:
+            for e in events:
+                await session.publish(e)
+                timer += 1
     print(f"\tAdd: took {timer.duration:.2f} seconds. {timer.throughput():.1f}/sec")
     return timer.throughput()
 
```

```diff
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -17,7 +17,6 @@
     "electrum_ecc",
     "aiohttp>=3.11.0,<4.0.0",
     "aiohttp_socks>=0.9.2",
-    "aiorpcx>=0.22.0,<0.26",  # for taskgroup. remove when we use python 3.11
 ]
 classifiers = [
     "Development Status :: 2 - Pre-Alpha",
```

Check nothing else uses aiorpcx: `grep -rn aiorpcx src tests` → no output.

- [ ] **Step 6: Changelog and README**

In `docs/history.md`, insert above `* **Release v0.1.0 (2025-12-11)**`:

```markdown
* **Release v0.2.0 (unreleased)**

    - new `RelayPool` / `NostrSession` API: one connection per relay shared by all
      sessions of a process, per-session relay sets, idle relays linger before closing
    - `Relay` rewritten: one supervisor task per connection with reconnect backoff,
      subscriptions survive reconnects, consumers can never block the connection,
      malformed messages are dropped without stalling it, heartbeats detect dead sockets
    - publishing reports per-relay results and raises `PublishError` if no relay accepted
    - NIP-42 AUTH uses a random key per connection unless one is configured
    - `Manager` is now a thin wrapper around `RelayPool` (breaking: its internals changed)
    - add `create_event` helper; `aionostr mirror` and `aionostr bench` work again
    - dependencies: `aiorpcx` is no longer required

```

In `README.md`, insert after the `aionostr mirror ...` example block (before `Set environment variables:`):

````markdown
* Share relay connections between several consumers:

```python
from electrum_aionostr import RelayPool, create_event
from electrum_aionostr.key import PrivateKey

private_key = PrivateKey()
async with RelayPool() as pool:
    pool.set_default_relays(['wss://nos.lol', 'wss://nostr.mom'])
    session = pool.open_session(name='example', extra_relays=['wss://relay.damus.io'])
    await session.publish(create_event(private_key, kind=1, content='hello'))
    async for event in session.get_events({'kinds': [1], 'limit': 10}):
        print(event)
```

````

- [ ] **Step 7: Run tests and lint**

Run: `PYTHONPATH=src python3 -m pytest -q tests`
Expected: `24 passed`.
Run the lint gate on `src tests` (Global Constraints). Expected: only the 2 pre-existing W293 in `delegation.py`.
Run the benchmark port against the local relay:

```bash
PYTHONPATH=src:tests python3 -c "
import asyncio
from relay_server import LocalRelay
from electrum_aionostr import benchmark
async def main():
    relay = LocalRelay(); await relay.start()
    await benchmark.adds_per_second(relay.url, 20)
    print('published', len(relay.published_ids()))
    await relay.stop()
asyncio.run(main())"
```

Expected: an `Add: took ...` line and `published 20`.

- [ ] **Step 8: Commit**

```bash
git add -A src tests pyproject.toml docs/history.md README.md
git commit -m "Manager: reimplement as a wrapper around RelayPool, prepare 0.2.0

Also fix 'aionostr mirror' (Manager.add_event has no check_response)
and port the 'aionostr bench' setup to the pool. aiorpcx is no longer
used."
```

---

## Part B — Electrum

### Task 5: `NostrManager` on `Network`

**Files:**
- Create: `electrum/nostr.py`
- Modify: `electrum/network.py`, `electrum/commands.py`, `electrum/gui/qt/network_dialog.py`, `electrum/gui/qml/qeconfig.py`, `contrib/requirements/requirements.txt`
- Commit (separately): `docs/superpowers/plans/2026-09-29-nostr-connection-manager.md` (this plan, already on disk)

**Interfaces:**
- Consumes: `electrum_aionostr.RelayPool`, `NostrSession` (Tasks 3/4).
- Produces: `network.nostr: NostrManager` with `open_session(*, name: str, extra_relays: Iterable[str] = (), use_default_relays: bool = True) -> NostrSession` (must be called on the asyncio thread) and `async stop()`; util event `nostr_relays_changed` (no arguments) fired whenever `NOSTR_RELAYS` is edited.

No unit test (spec §7: `NostrManager` is thin wiring). Verification is a smoke script against in-process relays.

- [ ] **Step 1: Commit this plan on its own**

```bash
cd /home/user/electrum-vm
git add docs/superpowers/plans/2026-09-29-nostr-connection-manager.md
git commit -m "docs: implementation plan for shared nostr connection manager"
```

- [ ] **Step 2: Write the smoke script** (not committed) — create `/tmp/nostr_manager_smoke.py`:

```python
"""Smoke test for electrum.nostr.NostrManager against in-process relays. Not a unit test."""
import asyncio, sys, tempfile, types
sys.path.insert(0, sys.argv[1])  # aionostr tests dir (for relay_server)
from relay_server import LocalRelay
from electrum import util
from electrum.simple_config import SimpleConfig
from electrum.network import ProxySettings
from electrum.nostr import NostrManager


async def main():
    first, second = LocalRelay(), LocalRelay()
    await first.start(); await second.start()
    config = SimpleConfig({'electrum_path': tempfile.mkdtemp()})
    config.NOSTR_RELAYS = first.url
    network = types.SimpleNamespace(config=config, proxy=ProxySettings())
    nostr = NostrManager(network)
    swap = nostr.open_session(name='swap-client')
    psbt = nostr.open_session(name='psbt')
    assert await swap.wait_connected(5) and await psbt.wait_connected(5)
    assert first.connections == 1, first.connections
    await swap.close()
    swap = nostr.open_session(name='swap-client')  # reopened: reuses the lingering socket
    assert await swap.wait_connected(0.1) and first.connections == 1

    config.NOSTR_RELAYS = second.url
    util.trigger_callback('nostr_relays_changed')
    for _ in range(200):
        if psbt.connected_relays() == [second.url]:
            break
        await asyncio.sleep(0.01)
    assert psbt.relays == {second.url}, psbt.relays

    util.trigger_callback('proxy_set', network.proxy)  # same (no) proxy: every relay reconnects
    for _ in range(300):
        if second.connections == 2 and psbt.connected_relays():
            break
        await asyncio.sleep(0.01)
    assert second.connections == 2, second.connections

    await nostr.stop()
    for _ in range(300):
        if first.open_sockets == second.open_sockets == 0:
            break
        await asyncio.sleep(0.01)
    assert first.open_sockets == second.open_sockets == 0
    print("NostrManager smoke test OK")


loop, stop_loop, loop_thread = util.create_and_start_event_loop()
try:
    asyncio.run_coroutine_threadsafe(main(), loop).result(60)
finally:
    loop.call_soon_threadsafe(stop_loop.set_result, 1)
    loop_thread.join(timeout=5)
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd /home/user/electrum-vm && PYTHONPATH=/home/user/local-dev/electrum-aionostr/src python3 /tmp/nostr_manager_smoke.py /home/user/local-dev/electrum-aionostr/tests`
Expected: `ModuleNotFoundError: No module named 'electrum.nostr'`.

- [ ] **Step 4: Create `electrum/nostr.py`**:

```python
import ssl
from typing import TYPE_CHECKING, Iterable, Optional, Tuple

from electrum_aionostr import RelayPool, NostrSession

from .logging import Logger
from .util import (
    EventListener, event_listener, ca_path, get_asyncio_loop, get_running_loop,
    make_aiohttp_proxy_connector,
)

if TYPE_CHECKING:
    from aiohttp_socks import ProxyConnector
    from .network import Network


class NostrManager(Logger, EventListener):
    """
    Owns the process-wide nostr RelayPool, so that all features (swaps, plugins, ...) share
    one connection per relay. Nothing connects until the first session is opened.
    """
    LINGER_SEC = 180  # keep unused relay connections this long, in case they are needed again

    def __init__(self, network: 'Network'):
        Logger.__init__(self)
        self.network = network
        self.config = network.config
        self._ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        self._pool = None  # type: Optional[RelayPool]
        self._stopped = False
        self.register_callbacks()

    def open_session(
        self,
        *,
        name: str,
        extra_relays: Iterable[str] = (),
        use_default_relays: bool = True,
    ) -> NostrSession:
        """A session on the configured relays (NOSTR_RELAYS) plus extra_relays. Close it when done."""
        assert get_running_loop() == get_asyncio_loop(), "must be called on the asyncio thread"
        if self._stopped:
            raise Exception("nostr manager already stopped")
        if self._pool is None:
            proxy, connect_timeout = self._get_proxy()
            aionostr_logger = self.logger.getChild('aionostr')
            aionostr_logger.setLevel('INFO')  # DEBUG is very verbose
            self._pool = RelayPool(
                log=aionostr_logger,
                ssl_context=self._ssl_context,
                proxy=proxy,
                connect_timeout=connect_timeout,
                linger_sec=self.LINGER_SEC,
            )
            self._pool.set_default_relays(self.config.get_nostr_relays())
        return self._pool.open_session(name=name, extra_relays=extra_relays, use_default_relays=use_default_relays)

    async def stop(self) -> None:
        self._stopped = True
        self.unregister_callbacks()
        if self._pool is not None:
            await self._pool.close()

    def _get_proxy(self) -> Tuple[Optional['ProxyConnector'], float]:
        proxy = self.network.proxy
        if proxy and proxy.enabled:
            return make_aiohttp_proxy_connector(proxy, self._ssl_context), 10
        return None, 5

    @event_listener
    async def on_event_proxy_set(self, *args):
        if self._pool is None:
            return  # the pool gets created with the current proxy
        proxy, connect_timeout = self._get_proxy()
        await self._pool.set_proxy(proxy, connect_timeout=connect_timeout)

    @event_listener
    def on_event_nostr_relays_changed(self, *args):
        if self._pool is None:
            return
        self._pool.set_default_relays(self.config.get_nostr_relays())
```

- [ ] **Step 5: Wire it up** — apply:

```diff
--- a/electrum/network.py
+++ b/electrum/network.py
@@ -58,6 +58,7 @@
 from .i18n import _
 from .logging import get_logger, Logger
 from .fee_policy import FeeHistogram, FeeTimeEstimates, FEE_ETA_TARGETS
+from .nostr import NostrManager
 
 
 if TYPE_CHECKING:
@@ -401,6 +402,9 @@
         self.fee_estimates = FeeTimeEstimates()
         self.last_time_fee_estimates_requested = 0  # zero ensures immediate fees
 
+        # shared nostr relay connections, used by swaps and plugins
+        self.nostr = NostrManager(self)
+
     def has_internet_connection(self) -> bool:
         """Our guess whether the device has Internet-connectivity."""
         return self._has_ever_managed_to_connect_to_server
@@ -1252,6 +1256,8 @@
 
     @log_exceptions
     async def stop(self, *, full_shutdown: bool = True):
+        if full_shutdown:
+            await self.nostr.stop()
         if not self._was_started:
             self.logger.info("not stopping network as it was never started")
             return
```

```diff
--- a/electrum/commands.py
+++ b/electrum/commands.py
@@ -419,6 +419,8 @@
         else:
             cv = self.config.cv.from_key(key)
             cv.set(value)
+        if key == SimpleConfig.NOSTR_RELAYS.key():
+            util.trigger_callback('nostr_relays_changed')
 
     @command('')
     async def setconfig(self, key, value):
```

```diff
--- a/electrum/gui/qt/network_dialog.py
+++ b/electrum/gui/qt/network_dialog.py
@@ -37,7 +37,7 @@
 from electrum.interface import ServerAddr, PREFERRED_NETWORK_PROTOCOL
 from electrum.network import Network, ProxySettings, is_valid_host, is_valid_port
 from electrum.logging import get_logger
-from electrum.util import is_valid_websocket_url
+from electrum.util import is_valid_websocket_url, trigger_callback
 from electrum.gui import messages
 
 from electrum.gui.common_qt.util import QtEventListener, qt_event_listener
@@ -625,15 +625,19 @@
     def add_relay(self):
         relay = self.relay_edit.text()
         self.config.add_nostr_relay(relay)
-        self.update_list()
+        self.on_relays_changed()
 
     def remove_relay(self):
         item = self.relays_list.currentItem()
         if item is None:
             return
         self.config.remove_nostr_relay(item.text())
-        self.update_list()
+        self.on_relays_changed()
 
     def reset_relays(self):
         self.config.NOSTR_RELAYS = None
+        self.on_relays_changed()
+
+    def on_relays_changed(self):
         self.update_list()
+        trigger_callback('nostr_relays_changed')
```

```diff
--- a/electrum/gui/qml/qeconfig.py
+++ b/electrum/gui/qml/qeconfig.py
@@ -7,7 +7,7 @@
 from electrum.bitcoin import TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
 from electrum.i18n import set_language, get_gui_lang_names
 from electrum.logging import get_logger
-from electrum.util import base_unit_name_to_decimal_point
+from electrum.util import base_unit_name_to_decimal_point, trigger_callback
 from electrum.gui import messages
 
 from .qetypes import QEAmount
@@ -313,6 +313,7 @@
         if nostr_relays != self.config.NOSTR_RELAYS:
             self.config.NOSTR_RELAYS = nostr_relays if nostr_relays else None
             self.nostrRelaysChanged.emit()
+            trigger_callback('nostr_relays_changed')
 
     swapServerNPubChanged = pyqtSignal()
     @pyqtProperty(str, notify=swapServerNPubChanged)
```

```diff
--- a/contrib/requirements/requirements.txt
+++ b/contrib/requirements/requirements.txt
@@ -6,7 +6,7 @@
 certifi
 jsonpatch
 electrum_ecc>=0.0.4,<0.1
-electrum_aionostr>=0.1.0,<0.2
+electrum_aionostr>=0.2.0,<0.3
 
 # - upper limit to avoid needing hatchling at build-time :/
 #   (however newer versions should work at runtime)
```

Note: `contrib/deterministic-build/requirements.txt` pins `electrum-aionostr==0.1.0` with hashes; it can only be updated once 0.2.0 is published. Leave it.

- [ ] **Step 6: Verify**

Run the smoke script again (Step 3 command). Expected: `NostrManager smoke test OK`. Run it 3 times.
Run: `PYTHONPATH=/home/user/local-dev/electrum-aionostr/src python3 -m pytest -q tests/test_network.py tests/test_commands.py`
Expected: all pass.
Run the lint gate on `electrum/nostr.py electrum/network.py electrum/commands.py electrum/gui/qt/network_dialog.py electrum/gui/qml/qeconfig.py`. Expected: `0`.

- [ ] **Step 7: Commit**

```bash
git add electrum/nostr.py electrum/network.py electrum/commands.py electrum/gui/qt/network_dialog.py electrum/gui/qml/qeconfig.py contrib/requirements/requirements.txt
git commit -m "nostr: add NostrManager, shared relay connections on network.nostr

The pool is only created when the first session is opened. It follows
proxy changes and edits of the nostr relay list (new
'nostr_relays_changed' event). Requires electrum-aionostr 0.2.0."
```

### Task 6: Swap `NostrTransport` on a session

**Files:**
- Modify: `electrum/submarine_swaps.py`
- Test: `tests/test_submarine_swaps.py`

**Interfaces:**
- Consumes: `network.nostr.open_session` (Task 5); `electrum_aionostr.NostrSession`, `PublishError`, `create_event`; `electrum_aionostr.util.normalize_url`.
- Produces: `NostrTransport.nostr_session: Optional[NostrSession]` (replaces `relay_manager`, `get_relay_manager()`, `relays`, `ssl_context`, `nostr_private_key`). `send_direct_message()` signs once and re-sends the same event on retries.

- [ ] **Step 1: Write the failing test** — apply this diff to `tests/test_submarine_swaps.py`:

```diff
--- a/tests/test_submarine_swaps.py
+++ b/tests/test_submarine_swaps.py
@@ -19,6 +19,7 @@
 from electrum.submarine_swaps import (
     SwapManager, SwapData, NostrTransport, SwapServerTransport, LOCKTIME_DELTA_REFUND,
     MIN_LOCKTIME_DELTA_FOR_CLAIM, SPENDER_FINALITY_DELAY, _construct_swap_scriptcode)
+from electrum_aionostr import PublishError, PublishResult
 from electrum.transaction import (
     PartialTransaction, PartialTxOutput, Transaction, TxOutput, TxOutpoint)
 from electrum.txbatcher import TxBatcher
@@ -834,6 +835,40 @@
             await asyncio.open_connection('localhost', port)
 
 
+class TestNostrTransport(ElectrumTestCase):
+
+    def setUp(self):
+        super().setUp()
+        self.config = SimpleConfig({'electrum_path': self.electrum_path})
+
+    async def test_send_direct_message_retry_resends_the_same_event(self):
+        """A retry must not create a second request: the server would handle it twice."""
+        class FlakySession:  # the first publish times out, like a relay that did not answer
+            def __init__(self):
+                self.published = []
+
+            async def publish(self, event, *, relays=None, timeout=None):
+                self.published.append(event)
+                if len(self.published) == 1:
+                    raise PublishError([PublishResult('wss://relay.example', False, 'timeout')])
+                return PublishResult('wss://relay.example', True, '')
+
+        wallet = mock.MagicMock()
+        wallet.config = self.config
+        wallet.db.get_dict.return_value = {}
+        sm = SwapManager(wallet=wallet, lnworker=mock.MagicMock())
+        sm.network = mock.Mock(proxy=None)
+        transport = NostrTransport(self.config, sm, generate_random_keypair())
+        transport.nostr_session = session = FlakySession()
+        server_pubkey = generate_random_keypair().pubkey.hex()[2:]
+
+        event_id = await transport.send_direct_message(server_pubkey, '{"method": "createswap"}', retries=1)
+
+        self.assertEqual(2, len(session.published))
+        self.assertEqual(session.published[0].id, session.published[1].id)
+        self.assertEqual(event_id, session.published[0].id)
+
+
 class TestSwapServerPlugin(ElectrumTestCase):
     """The plugin serves swaps with the first wallet the daemon loads."""
 
```

- [ ] **Step 2: Run it to verify it fails**

Run: `PYTHONPATH=/home/user/local-dev/electrum-aionostr/src python3 -m pytest -q tests/test_submarine_swaps.py -k NostrTransport`
Expected: FAIL (`AssertionError: 2 != 0`: the old code publishes through `relay_manager`, which is `None`, and `@ignore_exceptions` swallows the error).

- [ ] **Step 3: Implement** — apply:

```diff
--- a/electrum/submarine_swaps.py
+++ b/electrum/submarine_swaps.py
@@ -1,7 +1,6 @@
 import asyncio
 import json
 import os
-import ssl
 import threading
 from concurrent.futures import Future
 from typing import TYPE_CHECKING, Optional, Dict, Sequence, Tuple, Iterable, List, Callable
@@ -16,8 +15,9 @@
 
 import electrum_aionostr as aionostr
 import electrum_aionostr.key
+from electrum_aionostr import NostrSession, PublishError, create_event
 from electrum_aionostr.event import Event
-from electrum_aionostr.util import to_nip19
+from electrum_aionostr.util import to_nip19, normalize_url
 
 from collections import defaultdict
 
@@ -35,8 +35,8 @@
     match_script_against_template, OPPushDataGeneric, OPPushDataPubkey, TxOutput,
 )
 from .util import (
-    log_exceptions, ignore_exceptions, BelowDustLimit, OldTaskGroup, ca_path, gen_nostr_ann_pow,
-    get_nostr_ann_pow_amount, make_aiohttp_proxy_connector, get_running_loop, get_asyncio_loop, wait_for2,
+    log_exceptions, ignore_exceptions, BelowDustLimit, OldTaskGroup, gen_nostr_ann_pow,
+    get_nostr_ann_pow_amount, get_running_loop, get_asyncio_loop, wait_for2,
     run_sync_function_on_asyncio_thread, trigger_callback, NoDynamicFeeEstimates, UserFacingException, now
 )
 from .lnutil import hex_to_bytes, Keypair, SENT, RECEIVED, MIN_FINAL_CLTV_DELTA_ACCEPTED, PaymentFailure
@@ -58,7 +58,6 @@
     from .lnworker import LNWallet
     from .lnchannel import Channel
     from .simple_config import SimpleConfig
-    from aiohttp_socks import ProxyConnector
 
 
 SWAP_TX_SIZE = 150  # default tx size, used for mining fee estimation
@@ -1915,11 +1914,9 @@
         SwapServerTransport.__init__(self, config=config, sm=sm)
         self._offers = {}  # type: Dict[str, SwapOffer]
         self.private_key = keypair.privkey
-        self.nostr_private_key = to_nip19('nsec', keypair.privkey.hex())
         self.nostr_pubkey = keypair.pubkey.hex()[2:]
         self.dm_replies = {}  # type: Dict[tuple[str, str], asyncio.Future[dict]]
-        self.ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
-        self.relay_manager = None  # type: Optional[aionostr.Manager]
+        self.nostr_session = None  # type: Optional[NostrSession]
         self._main_loop_task = None  # type: Optional[asyncio.Task]
         self.taskgroup = OldTaskGroup()
         self._last_swapserver_relays = self._load_last_swapserver_relays()  # type: Optional[Sequence[str]]
@@ -1949,13 +1946,13 @@
     @log_exceptions
     async def main_loop(self):
         self.logger.info(f'starting nostr transport with pubkey: {self.nostr_pubkey}')
-        self.logger.info(f'nostr relays: {self.relays}')
-        self.relay_manager = self.get_relay_manager()
-        await self.relay_manager.connect()
-        connected_relays = self.relay_manager.relays
-        self.logger.info(f'connected relays: {[relay.url for relay in connected_relays]}')
-        if connected_relays:
-            self.is_connected.set()
+        if self.sm.is_server:
+            self.nostr_session = self.network.nostr.open_session(name='swap-server')
+        else:
+            # also use the relays of the swap server we used last time
+            self.nostr_session = self.network.nostr.open_session(
+                name='swap-client', extra_relays=self._last_swapserver_relays or [])
+        self.logger.info(f'nostr relays: {sorted(self.nostr_session.relays)}')
         if self.sm.is_server:
             tasks = [
                 self.check_direct_messages(),
@@ -1967,6 +1964,7 @@
                 self._get_pairs_loop(),
                 self.update_relays()
             ]
+        tasks.append(self._set_connected_when_ready())
         try:
             async with self.taskgroup as group:
                 for task in tasks:
@@ -1983,42 +1981,21 @@
         self.is_connected.clear()
         if self._main_loop_task is not None:
             # note: main_loop is not in the taskgroup below (it owns it), so cancel it here.
-            #       Otherwise it could still be about to connect to the relays, and we would
-            #       not even have a relay_manager to close yet.
+            #       Otherwise it could still be about to open its nostr session, and we would
+            #       not even have a session to close yet.
             self._main_loop_task.cancel()
             self._main_loop_task = None
         await self.taskgroup.cancel_remaining()
-        if self.relay_manager is not None:
-            # note: main_loop sets it, and it might not have run yet (or have failed)
-            await self.relay_manager.close()
+        if self.nostr_session is not None:
+            # note: main_loop opens it, and it might not have run yet (or have failed).
+            # The relays stay connected for a while, the next transport can reuse them.
+            await self.nostr_session.close()
         self.logger.info("nostr transport shut down")
 
-    @property
-    def relays(self):
-        our_relays = self.config.NOSTR_RELAYS.split(',') if self.config.NOSTR_RELAYS else []
-        if self.sm.is_server:
-            return our_relays
-        last_swapserver_relays = self._last_swapserver_relays or []
-        return list(set(our_relays + last_swapserver_relays))
-
-    def get_relay_manager(self) -> aionostr.Manager:
-        assert get_running_loop() == get_asyncio_loop(), f"this must be run on the asyncio thread!"
-        if not self.relay_manager:
-            if self.uses_proxy:
-                proxy = make_aiohttp_proxy_connector(self.network.proxy, self.ssl_context)
-            else:
-                proxy: Optional['ProxyConnector'] = None
-            nostr_logger = self.logger.getChild('aionostr')
-            nostr_logger.setLevel('INFO')  # DEBUG is very verbose with aionostr
-            return aionostr.Manager(
-                self.relays,
-                private_key=self.nostr_private_key,
-                log=nostr_logger,
-                ssl_context=self.ssl_context,
-                proxy=proxy,
-                connect_timeout=self.connect_timeout
-            )
-        return self.relay_manager
+    async def _set_connected_when_ready(self):
+        await self.nostr_session.wait_connected()
+        self.logger.info(f'connected relays: {self.nostr_session.connected_relays()}')
+        self.is_connected.set()
 
     def get_offer(self, pubkey: str) -> Optional[SwapOffer]:
         return self._offers.get(pubkey)
@@ -2052,16 +2029,12 @@
         tags = [['d', f'electrum-swapserver-{self.NOSTR_EVENT_VERSION}'],
                 ['r', 'net:' + constants.net.NET_NAME],
                 ['expiration', str(now() + self.OFFER_UPDATE_INTERVAL_SEC + 10)]]
+        event = create_event(self.private_key, kind=self.USER_STATUS_NIP38, tags=tags, content=json.dumps(offer))
         try:
-            event_id = await aionostr._add_event(
-                self.relay_manager,
-                kind=self.USER_STATUS_NIP38,
-                tags=tags,
-                content=json.dumps(offer),
-                private_key=self.nostr_private_key)
-            self.logger.info(f"published offer {event_id}")
-        except asyncio.TimeoutError as e:
-            self.logger.warning(f"failed to publish swap offer: {str(e)}")
+            await self.nostr_session.publish(event)
+            self.logger.info(f"published offer {event.id}")
+        except PublishError as e:
+            self.logger.warning(f"failed to publish swap offer: {e}")
 
     @ignore_exceptions
     @log_exceptions
@@ -2070,24 +2043,20 @@
         our_private_key = aionostr.key.PrivateKey(self.private_key)
         recv_pubkey_hex = aionostr.util.from_nip19(pubkey)['object'].hex() if pubkey.startswith('npub') else pubkey
         encrypted_msg = our_private_key.encrypt_message(content, recv_pubkey_hex)
-        try:
-            event_id = await aionostr._add_event(
-                self.relay_manager,
-                kind=self.EPHEMERAL_REQUEST,
-                content=encrypted_msg,
-                private_key=self.nostr_private_key,
-                tags=[['p', recv_pubkey_hex]],
-            )
-        except asyncio.TimeoutError:
-            self.logger.warning(f"sending message to {pubkey} failed: timeout. {retries=}")
-            if retries > 0:
-                return await self.send_direct_message(pubkey, content, retries=retries-1)
-            return None
-        return event_id
+        # sign only once: a retry re-sends the same event, so it cannot be handled twice
+        event = create_event(
+            self.private_key, kind=self.EPHEMERAL_REQUEST, content=encrypted_msg, tags=[['p', recv_pubkey_hex]])
+        for retries_left in reversed(range(retries + 1)):
+            try:
+                await self.nostr_session.publish(event)
+                return event.id
+            except PublishError as e:
+                self.logger.warning(f"sending message to {pubkey} failed: {e}. {retries_left=}")
+        return None
 
     @log_exceptions
     async def send_request_to_server(self, method: str, request_data: dict) -> dict:
-        self.logger.debug(f"swapserver req: method: {method} relays: {self.relays}")
+        self.logger.debug(f"swapserver req: method: {method} relays: {sorted(self.nostr_session.relays)}")
         request_data['method'] = method
         server_npub = self.config.SWAPSERVER_NPUB
         server_pubkey = aionostr.util.from_nip19(server_npub)['object'].hex()
@@ -2111,7 +2080,7 @@
             "#r": [f"net:{constants.net.NET_NAME}"],
             "since": now() - 60 * 60,
         }
-        async for event in self.relay_manager.get_events(query, single_event=False, only_stored=False):
+        async for event in self.nostr_session.get_events(query, single_event=False, only_stored=False):
             try:
                 content = json.loads(event.content)
                 if not isinstance(content, dict):
@@ -2193,28 +2162,29 @@
                 #       The relay will learn our IP and see the DM events we send.
                 #       If the swapserver operator is also running one of these relays, they will learn the IP
                 #       of their swap counterparties.
-                await self.relay_manager.update_relays(self.relays)
+                await self.nostr_session.set_extra_relays(latest_known_relays)
 
     async def rebroadcast_event(self, event: Event, server_relays: Sequence[str]):
         """If the relays of the origin server are different from our relays we rebroadcast the
         event to our relays so it gets spread more widely."""
         if not server_relays:
             return
-        rebroadcast_relays = [relay for relay in self.relay_manager.relays if
-                              relay.url not in server_relays]
-        for relay in rebroadcast_relays:
-            try:
-                res = await relay.add_event(event, check_response=True)
-            except Exception as e:
-                self.logger.debug(f"failed to rebroadcast event to {relay.url}: {e}")
-                continue
-            self.logger.debug(f"rebroadcasted event to {relay.url}: {res}")
+        server_relays = {normalize_url(url) for url in server_relays}
+        rebroadcast_relays = [url for url in self.nostr_session.connected_relays() if url not in server_relays]
+        if not rebroadcast_relays:
+            return
+        try:
+            res = await self.nostr_session.publish(event, relays=rebroadcast_relays)
+        except PublishError as e:
+            self.logger.debug(f"failed to rebroadcast event: {e}")
+            return
+        self.logger.debug(f"rebroadcasted event, accepted by {res.url}")
 
     @log_exceptions
     async def check_direct_messages(self):
         privkey = aionostr.key.PrivateKey(self.private_key)
         query = {"kinds": [self.EPHEMERAL_REQUEST], "limit":0, "#p": [self.nostr_pubkey]}
-        async for event in self.relay_manager.get_events(query, single_event=False, only_stored=False):
+        async for event in self.nostr_session.get_events(query, single_event=False, only_stored=False):
             try:
                 content = privkey.decrypt_message(event.content, event.pubkey)
                 content = json.loads(content)
```

- [ ] **Step 4: Verify**

Run: `PYTHONPATH=/home/user/local-dev/electrum-aionostr/src python3 -m pytest -q tests/test_submarine_swaps.py tests/test_commands.py`
Expected: all pass.
Run: `grep -n "relay_manager\|nostr_private_key\|ssl_context\|_add_event" electrum/submarine_swaps.py` → no output.
Lint gate on `electrum/submarine_swaps.py tests/test_submarine_swaps.py` → `0`.

- [ ] **Step 5: Commit**

```bash
git add electrum/submarine_swaps.py tests/test_submarine_swaps.py
git commit -m "submarine_swaps: use a nostr session instead of a relay Manager

Closing and reopening the swap dialog reuses the relay connections.
A retried request re-sends the same signed event, so the server
cannot handle it twice."
```

### Task 7: NWC on a session

**Files:**
- Modify: `electrum/plugins/nwc/nwcserver.py`

**Interfaces:**
- Consumes: `network.nostr.open_session`; `NostrSession`, `PublishError`, `create_event`.
- Produces: `NWCServer.nostr_session` (replaces `manager`, `get_relay_manager()`, `refresh_manager()`, `on_event_proxy_set()`, `relays`, `ssl_context`); `NWCServer.publish(event) -> bool`; constants `INFO_EVENT_RETRY_SEC = 60`, `RELAY_CONNECT_TIMEOUT_SEC = 30`.

No automated test (the plugin has none; the behaviour is covered by the pool tests). Verification: lint, import, and the manual check in Task 9.

- [ ] **Step 1: Implement** — apply:

```diff
--- a/electrum/plugins/nwc/nwcserver.py
+++ b/electrum/plugins/nwc/nwcserver.py
@@ -25,28 +25,23 @@
 import asyncio
 import json
 import time
-import ssl
-import logging
 import urllib.parse
 from typing import TYPE_CHECKING, Optional, List, Tuple, Awaitable
 
-import electrum_aionostr as aionostr
+from electrum_aionostr import NostrSession, PublishError, create_event
 from electrum_aionostr.event import Event as nEvent
 from electrum_aionostr.key import PrivateKey
 
 from electrum.lnworker import PaymentDirection
 from electrum.plugin import BasePlugin, hook
 from electrum.logging import Logger
-from electrum.util import log_exceptions, ca_path, OldTaskGroup, get_asyncio_loop, InvoiceError, \
-    LightningHistoryItem, event_listener, EventListener, make_aiohttp_proxy_connector, \
-    get_running_loop
+from electrum.util import log_exceptions, OldTaskGroup, get_asyncio_loop, InvoiceError, \
+    LightningHistoryItem, event_listener, EventListener
 from electrum.invoices import Invoice, Request, PR_UNKNOWN, PR_PAID, BaseInvoice, PR_INFLIGHT, PR_FAILED, PR_EXPIRED, PR_UNPAID
 from electrum import constants
 from electrum.lnutil import RECEIVED, PaymentFeeBudget
 
 if TYPE_CHECKING:
-    from aiohttp_socks import ProxyConnector
-
     from electrum.simple_config import SimpleConfig
     from electrum.wallet import Abstract_Wallet
 
@@ -90,8 +85,8 @@
         async def close():
             try:
                 await self.taskgroup.cancel_remaining()
-                if nwc_server.manager:
-                    await nwc_server.manager.close()
+                if nwc_server.nostr_session:
+                    await nwc_server.nostr_session.close()
             except Exception as e:
                 self.logger.exception(f"error stopping NWCServer: {e}")
 
@@ -192,6 +187,8 @@
     SUPPORTED_NOTIFICATIONS: list[str] = ["payment_sent", "payment_received"]
     SUPPORTED_ENCRYPTION_SCHEMES: set[str] = {'nip04'}
     INFO_EVENT_REBROADCAST_INTERVAL_SEC = 60 * 60 * 24
+    INFO_EVENT_RETRY_SEC = 60
+    RELAY_CONNECT_TIMEOUT_SEC = 30
 
     def __init__(
         self,
@@ -203,43 +200,26 @@
         self.config = config  # type: 'SimpleConfig'
         self.wallet = wallet  # type: 'Abstract_Wallet'
         self.connections = connection_storage  # type: dict[str, dict]  # client hex pubkey -> connection data
-        self.relays = config.NOSTR_RELAYS.split(",") or []  # type: List[str]
         self.taskgroup = None  # type: Optional[OldTaskGroup]
-        self.ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
-        self.manager = None  # type: Optional[aionostr.Manager]
+        self.nostr_session = None  # type: Optional[NostrSession]
         self.register_callbacks()
 
-    def get_relay_manager(self) -> aionostr.Manager:
-        assert get_asyncio_loop() == get_running_loop(), "NWCServer must run in the aio event loop"
-        nostr_logger = self.logger.getChild('aionostr')
-        nostr_logger.setLevel(logging.INFO)
-        network = self.wallet.lnworker.network
-        if network.proxy and network.proxy.enabled:
-            proxy = make_aiohttp_proxy_connector(network.proxy, self.ssl_context)
-        else:
-            proxy: Optional['ProxyConnector'] = None
-        return aionostr.Manager(
-            # ensure that we also connect to NWC_RELAY, even if it's not in the NOSTR_RELAYS
-            relays=set(self.config.NOSTR_RELAYS.split(",")) | {self.config.NWC_RELAY},  # type: ignore
-            private_key=PrivateKey().hex(),  # use random private key
-            log=nostr_logger,
-            ssl_context=self.ssl_context,
-            proxy=proxy
-        )
-
     @log_exceptions
     async def run(self) -> None:
         while True:
             # wait until connections have been set up and network is available
             while (not self.connections
-                        or not self.relays
                         or not self.wallet.network
                         or not self.wallet.network.is_connected()
                         or not self.wallet.lnworker):
                 await asyncio.sleep(5)
 
-            if not await self.refresh_manager():
-                await asyncio.sleep(30)
+            if self.nostr_session is None:
+                # ensure that we also connect to NWC_RELAY, even if it's not in the NOSTR_RELAYS
+                self.nostr_session = self.wallet.network.nostr.open_session(
+                    name='nwc', extra_relays=[self.config.NWC_RELAY])  # type: ignore
+            if not await self.nostr_session.wait_connected(timeout=self.RELAY_CONNECT_TIMEOUT_SEC):
+                self.logger.warning(f"Could not connect to any relays!")
                 continue
 
             try:
@@ -249,52 +229,23 @@
                     await tg.spawn(self.handle_requests())
             except Exception as e:
                 self.logger.exception(f"Restarting nwc event handler after exception: {e}")
-                if self.manager:  # close the manager so refresh_manager() will recreate it
-                    await self.manager.close()
-                    self.manager = None
                 await asyncio.sleep(60)
             finally:
                 self.taskgroup = None
                 self.logger.debug("nwc taskgroup exited")
 
-    async def refresh_manager(self) -> bool:
-        """Checks if manager is still connected to relays, if not recreates it and reconnects"""
-        if self.manager is None:
-            # on startup and proxy change
-            self.manager = self.get_relay_manager()
-
-        if len(self.manager.relays) <= 0 < len(self.relays):
-            # manager lost all connections (relays)
-            # setup new manager so relays are populated again
-            await self.manager.close()
-            self.manager = self.get_relay_manager()
-
-        if not self.manager.connected:
-            # not set in new manager instances
-            await self.manager.connect()
-
-        if len(self.manager.relays) <= 0:
-            # manager should still have relays after connecting
-            self.logger.warning(f"Could not connect to any relays!")
-            return False
-
-        return True
-
     def restart_event_handler(self) -> None:
         """To be called when the connections change so we restart with a new filter"""
         if tg := self.taskgroup:
             asyncio.run_coroutine_threadsafe(tg.cancel_remaining(), get_asyncio_loop())
 
-    @event_listener
-    def on_event_proxy_set(self, *args):
-        async def restart_manager():
-            if self.manager:
-                await self.manager.close()
-                self.manager = None
-            await asyncio.sleep(5)
-            self.restart_event_handler()
-            self.logger.info("proxy changed, restarting nwc plugin nostr transport")
-        asyncio.run_coroutine_threadsafe(restart_manager(), get_asyncio_loop())
+    async def publish(self, event: nEvent) -> bool:
+        try:
+            await self.nostr_session.publish(event)
+        except PublishError as e:
+            self.logger.warning(f"failed to publish nwc event of kind {event.kind}: {e}")
+            return False
+        return True
 
     async def handle_requests(self) -> None:
         query = {
@@ -303,7 +254,7 @@
             "limit": 0,  # requests only new events after creating this subscription
             "since": int(time.time())
         }
-        async for event in self.manager.get_events(query, single_event=False, only_stored=False):
+        async for event in self.nostr_session.get_events(query, single_event=False, only_stored=False):
             await self._handle_single_request(event)
 
     async def _handle_single_request(self, event: nEvent) -> None:
@@ -434,15 +385,13 @@
         if add_tags:
             tags.extend(add_tags)
 
-        await self.taskgroup.spawn(aionostr._add_event(
-            self.manager,
+        event = create_event(
+            our_secret,  # the private key we generated for this specific client
             kind=self.RESPONSE_EVENT_KIND,
             tags=tags,
             content=self.encrypt_to_pubkey(content, to_pubkey_hex),
-            # use the private key we generated for this specific client
-            private_key=our_secret
-            )
         )
+        await self.taskgroup.spawn(self.publish(event))
 
     @log_exceptions
     async def handle_pay_invoice(self, request_event: nEvent, params: dict) -> None:
@@ -948,6 +897,7 @@
         if self.SUPPORTED_ENCRYPTION_SCHEMES:
             tags.append(['encryption', ' '.join(self.SUPPORTED_ENCRYPTION_SCHEMES)])
         while True:
+            all_published = True
             for client_pubkey, connection in list(self.connections.items()):
                 if client_pubkey not in self.connections:
                     continue  # might was removed during sleep
@@ -955,34 +905,29 @@
                 if self.is_receive_only(client_pubkey):
                     supported_methods -= self.SUPPORTED_SPENDING_METHODS
                 content = ' '.join(supported_methods)
-                event_id = await aionostr._add_event(
-                    self.manager,
-                    kind=self.INFO_EVENT_KIND,
-                    tags=tags or None,
-                    content=content,
-                    private_key=connection['our_secret']
-                )
-                self.logger.debug(f"Published info event {event_id} to {client_pubkey}")
+                event = create_event(connection['our_secret'], kind=self.INFO_EVENT_KIND, tags=tags, content=content)
+                if await self.publish(event):
+                    self.logger.debug(f"Published info event {event.id} to {client_pubkey}")
+                else:
+                    all_published = False
                 await asyncio.sleep(3)  # try not to blast every event at once so they don't get rate limited
-            await asyncio.sleep(self.INFO_EVENT_REBROADCAST_INTERVAL_SEC)
+            await asyncio.sleep(self.INFO_EVENT_REBROADCAST_INTERVAL_SEC if all_published else self.INFO_EVENT_RETRY_SEC)
 
     def publish_notification_event(self, content: dict):
         """
         https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#notification-events
         """
-        if not self.taskgroup or not self.manager:
+        if not self.taskgroup or not self.nostr_session:
             return
         self.logger.debug(f"Publishing notification event: {content}")
         for client_pubkey, connection in list(self.connections.items()):
-            coro = self.taskgroup.spawn(aionostr._add_event(
-                self.manager,
+            event = create_event(
+                connection['our_secret'],
                 kind=self.NOTIFICATION_EVENT_KIND,
                 tags=[['p', client_pubkey]],
                 content=self.encrypt_to_pubkey(json.dumps(content), client_pubkey),
-                private_key=connection['our_secret']
-                )
             )
-            asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
+            asyncio.run_coroutine_threadsafe(self.taskgroup.spawn(self.publish(event)), get_asyncio_loop())
 
     def encrypt_to_pubkey(self, msg: str, pubkey: str) -> str:
         """
```

- [ ] **Step 2: Verify**

Run: `grep -n "self\.manager\|refresh_manager\|get_relay_manager\|_add_event\|ssl_context\|self\.relays" electrum/plugins/nwc/nwcserver.py` → no output.
Run: `PYTHONPATH=/home/user/local-dev/electrum-aionostr/src python3 -c "import electrum.plugins.nwc.nwcserver"` → no error.
Lint gate on `electrum/plugins/nwc` → `0`.

- [ ] **Step 3: Commit**

```bash
git add electrum/plugins/nwc/nwcserver.py
git commit -m "nwc: use a nostr session instead of a relay Manager

Waits for a connected relay before publishing, retries failed info
events after a minute instead of a day, and no longer tears down the
handler when a publish fails."
```

### Task 8: psbt_nostr on a session

**Files:**
- Modify: `electrum/plugins/psbt_nostr/psbt_nostr.py`

**Interfaces:**
- Consumes: `network.nostr.open_session`; `NostrSession`, `create_event`.
- Produces: `CosignerWallet.nostr_session` (opened at the start of `main_loop()`, before the wallet-sync wait; closed in `stop()`), replaces `nostr_manager()`, `ssl_context`, `on_event_proxy_set()`. `send_direct_messages()` raises `PublishError` when no relay accepted a message (the Qt/QML send paths already show `str(e)`).

- [ ] **Step 1: Implement** — apply:

```diff
--- a/electrum/plugins/psbt_nostr/psbt_nostr.py
+++ b/electrum/plugins/psbt_nostr/psbt_nostr.py
@@ -24,12 +24,10 @@
 # SOFTWARE.
 import asyncio
 import json
-import ssl
 import time
-from contextlib import asynccontextmanager
 
 import electrum_ecc as ecc
-import electrum_aionostr as aionostr
+from electrum_aionostr import NostrSession, create_event
 from electrum_aionostr.key import PrivateKey
 from typing import Dict, TYPE_CHECKING, Union, List, Tuple, Optional, Callable
 
@@ -40,14 +38,12 @@
 from electrum.plugin import BasePlugin
 from electrum.transaction import PartialTransaction, tx_from_any
 from electrum.util import (
-    log_exceptions, OldTaskGroup, ca_path, trigger_callback, event_listener, json_decode,
-    make_aiohttp_proxy_connector, run_sync_function_on_asyncio_thread,
+    log_exceptions, OldTaskGroup, trigger_callback, json_decode, run_sync_function_on_asyncio_thread,
 )
 from electrum.wallet import Multisig_Wallet
 
 if TYPE_CHECKING:
     from electrum.wallet import Abstract_Wallet
-    from aiohttp_socks import ProxyConnector
 
 # event kind used for nostr messages (with expiration tag)
 NOSTR_EVENT_KIND = 4
@@ -98,7 +94,6 @@
             if v < now() - self.KEEP_DELAY:
                 self.logger.info(f'deleting old event {k}')
                 self.known_events.pop(k)
-        self.ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
         self.logger.info(f"relays {self.config.NOSTR_RELAYS.split(',')}")
 
         self.cosigner_list = []  # type: List[Tuple[str, str]]
@@ -132,21 +127,15 @@
 
         self.messages = asyncio.Queue()
         self.taskgroup = OldTaskGroup()
+        self.nostr_session = None  # type: Optional[NostrSession]
         if self.network and self.nostr_pubkey:
             asyncio.run_coroutine_threadsafe(self.main_loop(), self.network.asyncio_loop)
 
-    @event_listener
-    async def on_event_proxy_set(self, *args):
-        # note: the callbacks get registered in the child classes of CosignerWallet
-        if not (self.network and self.nostr_pubkey):
-            return
-        await self.stop()
-        self.taskgroup = OldTaskGroup()
-        asyncio.run_coroutine_threadsafe(self.main_loop(), self.network.asyncio_loop)
-
     @log_exceptions
     async def main_loop(self):
         self.logger.info("starting taskgroup.")
+        # open the session right away, sending does not have to wait for the wallet to sync
+        self.nostr_session = self.network.nostr.open_session(name='psbt')
         try:
             # start processing PSBTs only after wallet is_up_to_date
             while not self.wallet.is_up_to_date():
@@ -161,83 +150,69 @@
 
     async def stop(self):
         await self.taskgroup.cancel_remaining()
-
-    @asynccontextmanager
-    async def nostr_manager(self):
-        if self.network.proxy and self.network.proxy.enabled:
-            proxy = make_aiohttp_proxy_connector(self.network.proxy, self.ssl_context)
-        else:
-            proxy: Optional['ProxyConnector'] = None
-        manager_logger = self.logger.getChild('aionostr')
-        manager_logger.setLevel("INFO")  # set to INFO because DEBUG is very spammy
-        async with aionostr.Manager(
-                relays=self.config.NOSTR_RELAYS.split(','),
-                private_key=self.nostr_privkey,
-                ssl_context=self.ssl_context,
-                proxy=proxy,
-                log=manager_logger
-        ) as manager:
-            yield manager
+        if self.nostr_session is not None:
+            await self.nostr_session.close()
+            self.nostr_session = None
 
     @log_exceptions
     async def send_direct_messages(self, messages: List[Tuple[str, dict]]):
-        our_private_key: PrivateKey = aionostr.key.PrivateKey(bytes.fromhex(self.nostr_privkey))
-        async with self.nostr_manager() as manager:
-            for pubkey, msg in messages:
-                encrypted_msg: str = our_private_key.encrypt_message(json.dumps(msg), pubkey)
-                eid = await aionostr._add_event(
-                    manager,
-                    kind=NOSTR_EVENT_KIND,
-                    content=encrypted_msg,
-                    private_key=self.nostr_privkey,
-                    tags=[['p', pubkey], ['expiration', str(int(now() + self.KEEP_DELAY))]])
-                self.logger.info(f'message sent to {pubkey}: {eid}')
+        """Raises PublishError if no relay accepted a message."""
+        if self.nostr_session is None:
+            raise Exception(_("Not connected to Nostr"))
+        our_private_key = PrivateKey(bytes.fromhex(self.nostr_privkey))
+        for pubkey, msg in messages:
+            encrypted_msg: str = our_private_key.encrypt_message(json.dumps(msg), pubkey)
+            event = create_event(
+                self.nostr_privkey,
+                kind=NOSTR_EVENT_KIND,
+                content=encrypted_msg,
+                tags=[['p', pubkey], ['expiration', str(int(now() + self.KEEP_DELAY))]])
+            await self.nostr_session.publish(event)
+            self.logger.info(f'message sent to {pubkey}: {event.id}')
 
     @log_exceptions
     async def check_direct_messages(self):
         privkey = PrivateKey(bytes.fromhex(self.nostr_privkey))
-        async with self.nostr_manager() as manager:
-            await manager.connect()
-            query = {
-                "kinds": [NOSTR_EVENT_KIND],
-                "limit": 100,
-                "#p": [self.nostr_pubkey],
-                "since": int(now() - self.KEEP_DELAY),
-            }
-            async for event in manager.get_events(query, single_event=False, only_stored=False):
-                if event.id in self.known_events:
-                    self.logger.info(f'known event {event.id} {util.age(event.created_at)}')
-                    continue
-                if not any(event.pubkey == pubkey for _xpub, pubkey in self.cosigner_list):
-                    self.logger.warning(f"got event from unknown author: {event.pubkey}")
-                    continue
-                if event.created_at > now() + self.KEEP_DELAY:
-                    # might be malicious
-                    continue
-                if event.created_at < now() - self.KEEP_DELAY:
-                    continue
-                self.logger.info(f'new event {event.id}')
-                try:
-                    message = privkey.decrypt_message(event.content, event.pubkey)
-                except Exception as e:
-                    self.logger.info(f'could not decrypt message {event.pubkey}')
-                    self.known_events[event.id] = now()
-                    continue
-                try:
-                    message = json_decode(message)
-                    if not isinstance(message, dict):
-                        raise Exception("malformed message, not dict")
-                    tx_hex = message.get('tx')
-                    label = message.get('label', '')
-                    tx = tx_from_any(tx_hex)
-                except Exception as e:
-                    self.logger.info(_("Unable to deserialize the transaction:") + "\n" + str(e))
-                    self.known_events[event.id] = now()
-                    continue
-                self.logger.info(f"received PSBT from {event.pubkey}")
-                trigger_callback('psbt_nostr_received', self.wallet, event.pubkey, event.id, tx, label)
-                await self.pending.wait()
-                self.pending.clear()
+        query = {
+            "kinds": [NOSTR_EVENT_KIND],
+            "limit": 100,
+            "#p": [self.nostr_pubkey],
+            "since": int(now() - self.KEEP_DELAY),
+        }
+        async for event in self.nostr_session.get_events(query, single_event=False, only_stored=False):
+            if event.id in self.known_events:
+                self.logger.info(f'known event {event.id} {util.age(event.created_at)}')
+                continue
+            if not any(event.pubkey == pubkey for _xpub, pubkey in self.cosigner_list):
+                self.logger.warning(f"got event from unknown author: {event.pubkey}")
+                continue
+            if event.created_at > now() + self.KEEP_DELAY:
+                # might be malicious
+                continue
+            if event.created_at < now() - self.KEEP_DELAY:
+                continue
+            self.logger.info(f'new event {event.id}')
+            try:
+                message = privkey.decrypt_message(event.content, event.pubkey)
+            except Exception as e:
+                self.logger.info(f'could not decrypt message {event.pubkey}')
+                self.known_events[event.id] = now()
+                continue
+            try:
+                message = json_decode(message)
+                if not isinstance(message, dict):
+                    raise Exception("malformed message, not dict")
+                tx_hex = message.get('tx')
+                label = message.get('label', '')
+                tx = tx_from_any(tx_hex)
+            except Exception as e:
+                self.logger.info(_("Unable to deserialize the transaction:") + "\n" + str(e))
+                self.known_events[event.id] = now()
+                continue
+            self.logger.info(f"received PSBT from {event.pubkey}")
+            trigger_callback('psbt_nostr_received', self.wallet, event.pubkey, event.id, tx, label)
+            await self.pending.wait()
+            self.pending.clear()
 
     def diagnostic_name(self):
         return self.wallet.diagnostic_name()
```

- [ ] **Step 2: Verify**

Run: `grep -n "nostr_manager\|ssl_context\|_add_event\|on_event_proxy_set" electrum/plugins/psbt_nostr/*.py` → no output.
Run: `PYTHONPATH=/home/user/local-dev/electrum-aionostr/src python3 -c "import electrum.plugins.psbt_nostr.psbt_nostr"` → no error.
Lint gate on `electrum/plugins/psbt_nostr` → `0`.

- [ ] **Step 3: Commit**

```bash
git add electrum/plugins/psbt_nostr/psbt_nostr.py
git commit -m "psbt_nostr: use one nostr session per wallet

Sending no longer opens new relay connections for every PSBT, works
before the wallet has synced, and reports an error when no relay
accepted the PSBT."
```

### Task 9: Whole-branch verification

**Files:** none (verification only; fix and commit in the task that owns the code if something fails).

- [ ] **Step 1: Library suite and lint**

Run: `cd ~/local-dev/electrum-aionostr && for i in 1 2 3; do PYTHONPATH=src python3 -m pytest -q tests | tail -1; done`
Expected: `24 passed` three times. Lint gate on `src tests`: only the 2 pre-existing W293.

- [ ] **Step 2: Electrum suite and lint**

Run: `cd /home/user/electrum-vm && PYTHONPATH=/home/user/local-dev/electrum-aionostr/src python3 -m pytest -q tests` (takes several minutes; pytest-xdist is not installed).
Expected: 0 failures. If something fails, first check whether it also fails on commit `5d70f4505` (before any code change) with the same command; only regressions are ours to fix.
Run the Electrum CI lint command from the repo root: `python3 -m flake8 . --count --select=... --ignore=... --show-source --statistics --exclude "*_pb2.py,electrum/_vendor/"` → `0`.

- [ ] **Step 3: Smoke script** — Task 5 Step 3 command. Expected: `NostrManager smoke test OK`.

- [ ] **Step 4: Shutdown with live sessions** (Review Focus 4)

Run this one-off check (not committed):

```bash
cd /home/user/electrum-vm && PYTHONPATH=/home/user/local-dev/electrum-aionostr/src python3 - /home/user/local-dev/electrum-aionostr/tests <<'EOF'
import asyncio, sys, tempfile, types
sys.path.insert(0, sys.argv[1])
from relay_server import LocalRelay
from electrum import util
from electrum.simple_config import SimpleConfig
from electrum.network import ProxySettings
from electrum.nostr import NostrManager
from electrum_aionostr import PoolClosed

async def main():
    relay = LocalRelay(); await relay.start()
    config = SimpleConfig({'electrum_path': tempfile.mkdtemp()}); config.NOSTR_RELAYS = relay.url
    nostr = NostrManager(types.SimpleNamespace(config=config, proxy=ProxySettings()))
    session = nostr.open_session(name='nwc')
    consumer = asyncio.create_task(_drain(session.get_events({'kinds': [23194]}, only_stored=False)))
    await asyncio.sleep(0.5)
    await nostr.stop()
    assert await asyncio.wait_for(consumer, 5) == []  # returned normally
    try:
        await session.wait_connected(1)
    except PoolClosed:
        print("shutdown OK")

async def _drain(gen):
    return [e async for e in gen]

loop, stop_loop, thread = util.create_and_start_event_loop()
try:
    asyncio.run_coroutine_threadsafe(main(), loop).result(30)
finally:
    loop.call_soon_threadsafe(stop_loop.set_result, 1); thread.join(5)
EOF
```

Expected: `shutdown OK`, no traceback.

- [ ] **Step 5: Real relays** (only if the machine has internet access; check with `python3 -c "import socket; socket.create_connection(('nos.lol', 443), 5)"`; otherwise hand these steps to the user)

Run Electrum on testnet with the GUI or daemon (`./run_electrum --testnet -v`, logs to stderr), then:
1. Open the swap dialog, close it, open it again within 3 minutes. Expected in the log: one `connected to wss://...` line per relay for the first open and none for the second.
2. With the psbt_nostr plugin on a multisig testnet wallet and the NWC plugin enabled with one connection, open the swap dialog. Expected: still one `connected to` line per relay URL in total.
3. Enable a SOCKS proxy in the network settings (Tor if available, Review Focus 1). Expected: every relay logs `disconnected from` / `connected to` again, and the swap dialog still finds providers.

- [ ] **Step 6: Report** — summarise results (test counts, lint, smoke, manual checks done or handed over) to the user. Do not push, and do not open PRs; the user decides how to integrate (superpowers:finishing-a-development-branch).

---

## Execution notes

Rulings made while executing this plan (the code in the tasks above is what was planned; the commits contain these changes on top):

- Task 1: `is_valid_relay_url` validates the raw stripped string (prefix `wss://` only when there is no `://`, require scheme ws/wss and a hostname) instead of the normalized one, which accepted `wss://`, `ws://` and `wss:///`. Added `tests/test_util.py::TestUtil::test_is_valid_relay_url` (trust boundary for peer-announced relay lists). All later expected library test counts are one higher (13 / 23 / 25).
- Task 2: `Relay` got a `_notify()` guard around every sink / state callback, a done-callback that logs a dying supervisor, `_close_ws` in its own `finally`, and a generation counter so a superseded supervisor exits even when Python < 3.12's `asyncio.wait_for` swallows a cancellation. The bad-message test also asserts that the connection was not dropped.
- Task 4: `Manager.connect()` cancels its waiters in a `finally` and reuses its session on retry, and `Manager.__aenter__` closes the manager if `connect()` raises (a cancelled `async with Manager(...)` used to leak a reconnecting pool).
